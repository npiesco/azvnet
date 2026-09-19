from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from azvnet import (
    AzureSession,
    AzvnetError,
    Bootstrap,
    Identity,
    credentials,
    private_text,
)
from azvnet.auth import CLI_STDIN_PROGRAM, checked
from azvnet.remote import (
    MAX_OUTPUT_BYTES,
    cleanup_after,
    completion_script,
    encrypt_payload,
    linux_envelope,
    linux_key_setup,
    decrypt_payload,
    parse_completion,
)
from azvnet.tofu import (
    configuration_bundle,
    guest_script,
    remote_arguments,
    variable_values,
)


def arm_response(
    stdout: str,
    stderr: str = "",
    *,
    code: str = "ProvisioningState/succeeded",
    returncode: int = 0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        ["az"],
        returncode,
        json.dumps(
            {
                "value": [
                    {
                        "code": code,
                        "level": "Info",
                        "message": f"Enable succeeded:\n[stdout]\n{stdout}\n[stderr]\n{stderr}",
                    }
                ]
            }
        ),
        "",
    )


class CredentialsTests(unittest.TestCase):
    def resolve(self, env, path=None, interactive=False):
        return credentials(
            tenant_id="tenant",
            subscription_id="subscription",
            client_id="client",
            environ=env,
            credential_file=path,
            interactive=interactive,
        )

    def test_every_identity_conflict_is_rejected(self):
        for key in ("ARM_TENANT_ID", "ARM_SUBSCRIPTION_ID", "ARM_CLIENT_ID"):
            with self.subTest(key=key), self.assertRaises(AzvnetError):
                self.resolve({"ARM_CLIENT_SECRET": "test-only-value", key: "other"})

    def test_environment_does_not_mutate(self):
        env = {"ARM_CLIENT_SECRET": "test-only-value"}
        original = dict(os.environ)
        with AzureSession(
            tenant_id="tenant",
            subscription_id="subscription",
            client_id="client",
            environ=env,
        ) as session:
            self.assertEqual(session.env["ARM_USE_CLI"], "false")
            self.assertEqual(env, {"ARM_CLIENT_SECRET": "test-only-value"})
        self.assertEqual(dict(os.environ), original)

    def test_private_file_mode_and_conflicts(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "credential"
            path.write_text(
                "Tenant: tenant\nClient ID: client\nSecret: test-only-value\n"
            )
            path.chmod(0o600)
            self.assertEqual(self.resolve({}, path)["ARM_CLIENT_ID"], "client")
            path.chmod(0o644)
            with self.assertRaises(AzvnetError):
                self.resolve({}, path)
            path.chmod(0o600)
            path.write_text(
                "Tenant: other\nClient ID: client\nSecret: test-only-value\n"
            )
            with self.assertRaises(AzvnetError):
                self.resolve({}, path)
            link = Path(scratch) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                private_text(link)

    def test_missing_credentials_fail_without_ambient_login(self):
        with self.assertRaises(AzvnetError):
            self.resolve({})

    def test_interactive_is_explicit(self):
        result = credentials(
            tenant_id="tenant",
            subscription_id="subscription",
            client_id=None,
            environ={},
            interactive=True,
        )
        self.assertEqual(result["ARM_USE_CLI"], "true")

    def test_subscription_argument_conflict_precedes_login(self):
        with AzureSession(
            tenant_id="tenant",
            subscription_id="subscription",
            client_id="client",
            environ={"ARM_CLIENT_SECRET": "test-only-value"},
        ) as session:
            for flags in (
                ["--subscription", "other"],
                ["-s", "other"],
                ["--subscription=other"],
            ):
                with (
                    self.subTest(flags=flags),
                    self.assertRaisesRegex(AzvnetError, "subscription"),
                ):
                    session.run("group", "list", *flags)

    def test_state_and_raw_outputs_require_capture_before_any_process(self):
        with AzureSession(
            tenant_id="tenant",
            subscription_id="subscription",
            client_id="client",
            environ={"ARM_CLIENT_SECRET": "test-only-value"},
        ) as session:
            for arguments in (("state", "pull"), ("show", "-json"), ("output", "-raw")):
                with (
                    self.subTest(arguments=arguments),
                    self.assertRaisesRegex(AzvnetError, "capture=True"),
                ):
                    session.local_tofu(*arguments, workdir=Path("."))


class CompletionTests(unittest.TestCase):
    token = "AZVNETtestinvocation123"

    def shell(self, script):
        return subprocess.run(
            ["bash"],
            input=completion_script(script, self.token),
            text=True,
            capture_output=True,
            check=False,
        )

    def rejects(self, result):
        diagnostics = io.StringIO()
        with redirect_stderr(diagnostics), self.assertRaises(AzvnetError):
            parse_completion(result, self.token)
        self.assertTrue(diagnostics.getvalue())

    def test_real_shell_success_preserves_output_and_not_stderr(self):
        shell = self.shell("printf 'hello\\n'; printf 'progress\\n' >&2")
        result = parse_completion(arm_response(shell.stdout, shell.stderr), self.token)
        self.assertEqual(result, ("hello\n", "progress\n"))

    def test_framed_capture_preserves_whitespace_and_literal_wrapper_text(self):
        shell = self.shell("printf '\\n  [stdout]\\n[stderr]\\n\\n'")
        self.assertEqual(
            parse_completion(arm_response(shell.stdout, shell.stderr), self.token),
            ("\n  [stdout]\n[stderr]\n\n", ""),
        )

    def test_real_shell_failure_never_proves_success(self):
        for script in ("false", "false | cat", "echo failure >&2; exit 23"):
            with self.subTest(script=script):
                shell = self.shell(script)
                self.assertNotEqual(shell.returncode, 0)
                self.assertNotIn(self.token, shell.stdout)
                self.rejects(arm_response(shell.stdout, shell.stderr))

    def test_rejects_stderr_substring_stale_duplicate_and_truncated_proofs(self):
        for output, error in (
            ("failed", self.token),
            ("prefix" + self.token, ""),
            ("AZVNETotherinvocation", ""),
            (self.token + "\n" + self.token, ""),
            (self.token + "\nafter", ""),
            (self.token[:-1], ""),
        ):
            self.rejects(arm_response(output, error))

    def test_cli_and_arm_failure_beat_completion_marker(self):
        self.rejects(arm_response(self.token, returncode=1))
        self.rejects(arm_response(self.token, code="ProvisioningState/failed"))

    def test_malformed_and_ambiguous_wrappers_fail_closed(self):
        for body in ("{}", "null", '{"value":[]}', '{"value":"bad"}'):
            self.rejects(subprocess.CompletedProcess(["az"], 0, body, "diagnostic"))
        self.rejects(arm_response("[stdout]\n" + self.token))

    def test_captured_process_failure_is_visible(self):
        output = io.StringIO()
        with redirect_stderr(output), self.assertRaises(subprocess.CalledProcessError):
            checked(["bash", "-c", "echo useful-diagnostic >&2; exit 7"], capture=True)
        self.assertIn("useful-diagnostic", output.getvalue())


class CleanupTests(unittest.TestCase):
    def test_cleanup_also_runs_before_yield_work_completes(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "owned"
            path.touch()
            with self.assertRaisesRegex(ValueError, "primary"):
                with cleanup_after(path.unlink):
                    raise ValueError("primary")
            self.assertFalse(path.exists())

    def test_cleanup_failure_cannot_replace_primary(self):
        missing = Path("/nonexistent/azvnet-cleanup-test")
        with redirect_stderr(io.StringIO()):
            try:
                with cleanup_after(missing.unlink):
                    raise ValueError("primary")
            except ValueError as error:
                self.assertIn("Cleanup also failed", error.__notes__[0])
            else:
                self.fail("primary exception swallowed")

    def test_cleanup_failure_fails_success(self):
        with self.assertRaises(FileNotFoundError):
            with cleanup_after(Path("/nonexistent/azvnet-cleanup-test").unlink):
                pass


class ConfigurationTests(unittest.TestCase):
    def test_explicit_bootstrap_capacity_and_subnet_configuration(self):
        regular = Bootstrap(
            "region", "subnet", "image", "size", subnet_cidr="10.0.1.0/24"
        )
        self.assertEqual(regular.capacity_arguments(), ["--priority", "Regular"])
        spot = Bootstrap(
            "region", "subnet", "image", "size", priority="Spot", max_price=-1
        )
        self.assertEqual(
            spot.capacity_arguments(),
            [
                "--priority",
                "Spot",
                "--eviction-policy",
                "Delete",
                "--max-price",
                "-1",
            ],
        )
        for values in (
            {"priority": "Spot"},
            {"max_price": 1},
            {"priority": "other"},
            {"subnet_cidr": "invalid"},
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                Bootstrap("region", "subnet", "image", "size", **values)

    def test_variable_serialization_preserves_structures(self):
        self.assertEqual(
            variable_values(
                {
                    "TF_VAR_flag": "true",
                    "TF_VAR_values": '[1,"x"]',
                    "TF_VAR_object": '{"a":2}',
                    "TF_VAR_text": "text",
                    "OTHER": "ignored",
                }
            ),
            {"flag": True, "values": [1, "x"], "object": {"a": 2}, "text": "text"},
        )

    def test_bundle_has_only_explicit_regular_members(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "main.tf").write_text('output "answer" { value = 42 }\n')
            (root / "terraform.tfstate").write_text("never bundle this")
            (root / "link.tf").symlink_to(root / "terraform.tfstate")
            bundle = configuration_bundle(root, ["main.tf"])
            with tarfile.open(fileobj=io.BytesIO(base64.b64decode(bundle))) as archive:
                self.assertEqual(archive.getnames(), ["main.tf"])
            for member in ("../outside", "link.tf", str(root / "main.tf")):
                with self.assertRaises(AzvnetError):
                    configuration_bundle(root, [member])

    def test_absolute_var_file_is_relocated_not_passed_through(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            path = root / "values.tfvars.json"
            path.write_text('{"flag":true}')
            args, files = remote_arguments(["plan", f"-var-file={path}"], root)
            self.assertEqual(args, ["plan", "-var-file=input-0.tfvars.json"])
            self.assertEqual(files, {"input-0.tfvars.json": path.read_bytes()})
            with self.assertRaises(AzvnetError):
                remote_arguments(["plan", "-var=secret=value"], root)


class ExecutableTests(unittest.TestCase):
    def test_sealed_output_bound_fails_without_disclosing_output(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            guest, caller = root / "guest", root / "caller"
            for directory in (guest, caller):
                subprocess.run(
                    ["bash", "-se"],
                    input=linux_key_setup(str(directory)),
                    text=True,
                    capture_output=True,
                    check=True,
                )
            payload = f"python3 -c 'print(\"x\" * {MAX_OUTPUT_BYTES})'"
            ciphertext = encrypt_payload(
                (guest / "cert.pem").read_text(), payload.encode()
            )
            result = subprocess.run(
                ["bash"],
                input=linux_envelope(
                    str(guest),
                    ciphertext,
                    (caller / "cert.pem").read_text(),
                ),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertIn("exceeds", result.stderr)
            for name in ("key.pem", "payload.sh", "stdout", "stderr", "response.json"):
                self.assertFalse((guest / name).exists())

    def test_encrypted_output_and_guest_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            guest, caller = root / "guest", root / "caller"
            for directory in (guest, caller):
                subprocess.run(
                    ["bash", "-se"],
                    input=linux_key_setup(str(directory)),
                    text=True,
                    capture_output=True,
                    check=True,
                )
            canary = "synthetic-output-canary"
            payload = f"echo {canary}; echo private-error >&2; exit 23"
            encrypted = encrypt_payload(
                (guest / "cert.pem").read_text(), payload.encode()
            )
            script = linux_envelope(
                str(guest), encrypted, (caller / "cert.pem").read_text()
            )
            result = subprocess.run(
                ["bash"], input=script, text=True, capture_output=True, check=True
            )
            self.assertNotIn(canary, result.stdout + result.stderr + script)
            self.assertTrue(result.stdout.startswith("AZVNETOUTPUT "))
            response = (guest / "response.b64").read_text()
            self.assertEqual(len(response), int(result.stdout.split()[1]))
            self.assertEqual(
                decrypt_payload(caller, response),
                (23, canary + "\n", "private-error\n"),
            )
            for name in (
                "key.pem",
                "cert.pem",
                "payload.sh",
                "stdout",
                "stderr",
                "response.json",
            ):
                self.assertFalse((guest / name).exists(), name)

    def test_actual_sealed_state_migration_and_serial_guard(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            source = root / "source"
            source.mkdir()
            (source / "main.tf").write_text(
                'resource "terraform_data" "example" { input = "synthetic-state-canary" }\n'
            )
            checked(["tofu", "init", "-input=false"], cwd=source, capture=True)
            checked(["tofu", "apply", "-auto-approve"], cwd=source, capture=True)
            state = (source / "terraform.tfstate").read_bytes()
            stale = json.loads(state)
            self.assertGreater(stale["serial"], 0)
            stale["serial"] -= 1
            version = json.loads(
                checked(["tofu", "version", "-json"], capture=True).stdout
            )["terraform_version"]
            script = guest_script(
                bundle=configuration_bundle(source, ["main.tf"]),
                arguments=["state", "push", "migrated.tfstate"],
                variables={},
                files={
                    "migrated.tfstate": state,
                    "stale.tfstate": json.dumps(stale).encode(),
                },
                tenant_id="tenant",
                subscription_id="subscription",
                identity=Identity("/identity", "client"),
                tofu_version=version,
            )
            script += """
tofu state list
if tofu state push stale.tfstate >rejected.out 2>&1; then
  echo 'stale state unexpectedly accepted' >&2
  exit 1
fi
if ! grep -E 'cannot import state with serial [0-9]+ over newer state with serial [0-9]+' rejected.out >/dev/null; then
  cat rejected.out >&2
  exit 1
fi
echo 'serial guard passed'
"""
            guest = root / "guest"
            setup = subprocess.run(
                ["bash", "-se"],
                input=linux_key_setup(str(guest)),
                text=True,
                capture_output=True,
                check=True,
            )
            encrypted = encrypt_payload(setup.stdout, script.encode())
            transport = linux_envelope(str(guest), encrypted)
            self.assertNotIn("synthetic-state-canary", transport)
            result = subprocess.run(
                ["bash"],
                input=transport,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("terraform_data.example", result.stdout)
            self.assertIn("serial guard passed", result.stdout)
            self.assertNotIn("synthetic-state-canary", result.stdout + result.stderr)
            self.assertFalse(guest.exists())

    def test_concurrent_guest_workdirs_are_distinct_and_removed(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "main.tf").write_text('output "directory" { value = path.cwd }\n')
            version = json.loads(
                checked(["tofu", "version", "-json"], capture=True).stdout
            )["terraform_version"]
            script = guest_script(
                bundle=configuration_bundle(root, ["main.tf"]),
                arguments=["apply", "-auto-approve", "-input=false", "-no-color"],
                variables={},
                files={},
                tenant_id="tenant",
                subscription_id="subscription",
                identity=Identity("/identity", "client"),
                tofu_version=version,
            )

            def execute():
                return subprocess.run(
                    ["bash"],
                    input=script,
                    text=True,
                    capture_output=True,
                    check=True,
                ).stdout

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _: execute(), range(2)))
            paths = [
                Path(
                    next(
                        line
                        for line in output.splitlines()
                        if line.startswith("directory = ")
                    ).split('"')[1]
                )
                for output in results
            ]
            self.assertNotEqual(paths[0], paths[1])
            self.assertTrue(all(not path.exists() for path in paths))

    def test_actual_guest_var_file_relocation(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "main.tf").write_text(
                'variable "mapping" { type = map(bool) }\n'
                'output "mapping" { value = var.mapping }\n'
            )
            local = root / "local-only.tfvars.json"
            local.write_text('{"mapping":{"correct":true}}')
            args, files = remote_arguments(
                ["apply", "-auto-approve", "-no-color", f"-var-file={local}"],
                root,
            )
            local.unlink()
            version = json.loads(
                checked(["tofu", "version", "-json"], capture=True).stdout
            )["terraform_version"]
            script = guest_script(
                bundle=configuration_bundle(root, ["main.tf"]),
                arguments=args,
                variables={},
                files=files,
                tenant_id="tenant",
                subscription_id="subscription",
                identity=Identity("/identity", "client"),
                tofu_version=version,
            )
            result = subprocess.run(
                ["bash"],
                input=script,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn('"correct" = true', result.stdout)
            self.assertNotIn(str(local), script)

    def test_actual_cli_stdin_bridge_without_authentication(self):
        interpreter = os.environ.get("AZVNET_CLI_PYTHON")
        self.assertIsNotNone(
            interpreter, "set AZVNET_CLI_PYTHON for the executable validation contract"
        )
        with tempfile.TemporaryDirectory() as scratch:
            result = subprocess.run(
                [interpreter, "-c", CLI_STDIN_PROGRAM],
                input=json.dumps(["version", "--output", "json"]),
                env={**os.environ, "AZURE_CONFIG_DIR": scratch},
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn("azure-cli", json.loads(result.stdout))

    def test_actual_cli_failure_is_not_empty_success(self):
        with tempfile.TemporaryDirectory() as scratch, redirect_stderr(io.StringIO()):
            with self.assertRaises(subprocess.CalledProcessError):
                checked(
                    ["az", "azvnet-invalid-command"],
                    env={**os.environ, "AZURE_CONFIG_DIR": scratch},
                    capture=True,
                )

    def test_actual_encryption_and_shell_payload(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / "guest"
            setup = subprocess.run(
                ["bash"],
                input=completion_script(linux_key_setup(str(root)), "setup123"),
                text=True,
                capture_output=True,
                check=True,
            )
            certificate, errors = parse_completion(
                arm_response(setup.stdout, setup.stderr), "setup123"
            )
            self.assertEqual(errors, "")
            self.assertEqual((root / "key.pem").stat().st_mode & 0o777, 0o600)
            corrupt_dir = Path(scratch) / "corrupt"
            corrupt_dir.mkdir(mode=0o700)
            for name in ("key.pem", "cert.pem"):
                (corrupt_dir / name).write_bytes((root / name).read_bytes())
                (corrupt_dir / name).chmod(0o600)
            payload = b'test "$(stat -c %a "$0")" = 600\nprintf "payload-executed\\n"\n'
            encrypted = encrypt_payload(certificate, payload)
            script = linux_envelope(str(root), encrypted)
            self.assertNotIn(payload.decode().strip(), script)
            result = subprocess.run(
                ["bash"], input=script, text=True, capture_output=True, check=True
            )
            self.assertEqual(result.stdout, "payload-executed\n")
            self.assertFalse(root.exists())
            corrupted = base64.b64encode(b"not CMS").decode()
            result = subprocess.run(
                ["bash"],
                input=linux_envelope(str(corrupt_dir), corrupted),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(corrupt_dir.exists())

    def test_actual_tofu_local_and_generated_guest_path(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "main.tf").write_text(
                'variable "values" { type = list(number) }\n'
                'variable "flag" { type = bool }\n'
                'output "result" { value = { values = var.values, flag = var.flag } }\n'
            )
            version = json.loads(
                checked(["tofu", "version", "-json"], capture=True).stdout
            )["terraform_version"]
            bundle = configuration_bundle(root, ["main.tf"])
            script = guest_script(
                bundle=bundle,
                arguments=["apply", "-auto-approve", "-input=false", "-no-color"],
                variables={"values": [2, 3], "flag": True},
                files={},
                tenant_id="tenant",
                subscription_id="subscription",
                identity=Identity("/identity", "client"),
                tofu_version=version,
            )
            environment = {**os.environ, "AZVNET_CANARY": "never-print-this"}
            result = subprocess.run(
                ["bash"],
                input=script,
                text=True,
                capture_output=True,
                check=True,
                env=environment,
            )
            self.assertIn("Apply complete!", result.stdout)
            self.assertNotIn("never-print-this", result.stdout)
            empty = guest_script(
                bundle=configuration_bundle(root, []),
                arguments=["validate", "-no-color"],
                variables={},
                files={},
                tenant_id="tenant",
                subscription_id="subscription",
                identity=Identity("/identity", "client"),
                tofu_version=version,
            )
            result = subprocess.run(
                ["bash"],
                input=empty,
                text=True,
                capture_output=True,
                check=True,
                env=environment,
            )
            self.assertNotIn("never-print-this", result.stdout)
            with AzureSession(
                tenant_id="tenant",
                subscription_id="subscription",
                client_id="client",
                environ={**os.environ, "ARM_CLIENT_SECRET": "test-only-value"},
            ) as session:
                session.local_tofu("init", "-backend=false", workdir=root, capture=True)
                session.local_tofu(
                    "apply",
                    "-auto-approve",
                    "-input=false",
                    workdir=root,
                    env={"TF_VAR_values": "[2,3]", "TF_VAR_flag": "true"},
                    capture=True,
                )
                output = session.local_tofu(
                    "output", "-json", workdir=root, capture=True
                )
                self.assertEqual(
                    json.loads(output.stdout)["result"]["value"],
                    {"flag": True, "values": [2, 3]},
                )
                with (
                    redirect_stderr(io.StringIO()),
                    self.assertRaises(subprocess.CalledProcessError),
                ):
                    session.local_tofu(
                        "azvnet-invalid-command", workdir=root, capture=True
                    )


if __name__ == "__main__":
    unittest.main()
