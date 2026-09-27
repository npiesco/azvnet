from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from azvnet import AzureSession, checked, non_azure_env, tf_var_environment
from azvnet.tofu import Identity, configuration_bundle, guest_script, remote_arguments

from test_core import restrict


class NativeGuestParityTests(unittest.TestCase):
    def test_scoped_file_credentials_reach_tofu_but_not_other_children(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            credential = root / "credential"
            credential.write_text(
                "Tenant: tenant\nClient ID: client\nSecret: synthetic-file-secret\n"
            )
            restrict(credential)
            # The Python running this suite is a real child interpreter on every platform.
            python = json.dumps(sys.executable)
            (root / "main.tf").write_text(
                'resource "terraform_data" "environment" {\n'
                ' provisioner "local-exec" {\n'
                f"  interpreter = [{python}, \"-c\"]\n"
                '  command = "import os, sys; '
                "sys.exit(os.environ.get('ARM_CLIENT_SECRET') != 'synthetic-file-secret')\"\n"
                " }\n}\n"
            )
            before = dict(os.environ)
            with AzureSession(
                tenant_id="tenant",
                subscription_id="subscription",
                credential_file=credential,
                environ=non_azure_env(),
            ) as session:
                session.local_tofu("init", "-backend=false", workdir=root, capture=True)
                session.local_tofu("apply", "-auto-approve", workdir=root, capture=True)
                checked(
                    [
                        sys.executable, "-c",
                        "import os, sys; sys.exit('ARM_CLIENT_SECRET' in os.environ)",
                    ],
                    env=non_azure_env(session.env),
                    capture=True,
                )
                self.assertEqual(
                    session.env["ARM_CLIENT_SECRET"], "synthetic-file-secret"
                )
            self.assertEqual(dict(os.environ), before)

    def script(self, root, arguments, *, env=None, variables=None, files=None):
        version = json.loads(
            checked(["tofu", "version", "-json"], capture=True).stdout
        )["terraform_version"]
        return guest_script(
            bundle=configuration_bundle(root, ["main.tf"]),
            arguments=arguments,
            variables=variables or {},
            files=files or {},
            tf_var_env=tf_var_environment(env or {}),
            tenant_id="tenant",
            subscription_id="subscription",
            identity=Identity("/identity", "client"),
            tofu_version=version,
        )

    def execute(self, script):
        return subprocess.run(
            ["bash"],
            input=script,
            text=True,
            capture_output=True,
            check=True,
            env={**non_azure_env(), "TF_HTTP_RETRY_MAX": "0"},
        ).stdout

    def test_explicit_init_backend_false_and_flags(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "main.tf").write_text(
                'terraform {\n backend "http" { address = "http://127.0.0.1:1/state" }\n}\n'
            )
            arguments = ["init", "-backend=false", "-input=false", "-no-color"]
            native = checked(["tofu", *arguments], cwd=root, capture=True)
            generated = self.execute(self.script(root, arguments))
            self.assertIn("successfully initialized", native.stdout)
            self.assertIn("successfully initialized", generated)
            with self.assertRaisesRegex(Exception, "dedicated API"):
                remote_arguments(["init", "-backend-config=secret"], root)

    def test_raw_declared_types_match_native(self):
        for declared, raw, expected in (
            ("map(string)", '{ key = "value" }', {"key": "value"}),
            ("string", '{"key":"value"}', '{"key":"value"}'),
            ("string", "", ""),
            ("string", "quote' dollar$ newline\ntext", "quote' dollar$ newline\ntext"),
        ):
            with (
                self.subTest(declared=declared, raw=raw),
                tempfile.TemporaryDirectory() as scratch,
            ):
                root = Path(scratch)
                (root / "main.tf").write_text(
                    f'variable "v" {{ type = {declared} }}\n'
                    'output "v" { value = var.v }\n'
                )
                env = {**non_azure_env(), "TF_VAR_v": raw}
                checked(
                    ["tofu", "init", "-backend=false"], cwd=root, env=env, capture=True
                )
                checked(
                    ["tofu", "apply", "-auto-approve", "-input=false"],
                    cwd=root,
                    env=env,
                    capture=True,
                )
                native = json.loads(
                    checked(
                        ["tofu", "output", "-json"], cwd=root, env=env, capture=True
                    ).stdout
                )
                output = self.execute(
                    self.script(
                        root, ["apply", "-auto-approve", "-input=false"], env=env
                    )
                    + "\ntofu output -json\n"
                )
                guest = json.loads(output[output.index('{\n  "v":') :])
                self.assertEqual(native["v"]["value"], expected)
                self.assertEqual(guest, native)

    def test_raw_env_typed_variables_and_explicit_file_precedence(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "main.tf").write_text(
                'variable "v" { type = string }\noutput "v" { value = var.v }\n'
            )
            for explicit, expected in ((False, "typed"), (True, "file")):
                arguments = ["apply", "-auto-approve", "-input=false"]
                if explicit:
                    arguments.append("-var-file=input.tfvars.json")
                script = self.script(
                    root,
                    arguments,
                    env={"TF_VAR_v": "environment"},
                    variables={"v": "typed"},
                    files={"input.tfvars.json": b'{"v":"file"}'},
                )
                output = self.execute(script + "\ntofu output -raw v\n")
                self.assertTrue(output.endswith(expected))

    def test_invalid_environment_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / "main.tf").write_text("")
            with self.assertRaisesRegex(ValueError, "shell identifiers"):
                self.script(root, ["init"], env={"TF_VAR_x;env": "value"})


if __name__ == "__main__":
    unittest.main()
