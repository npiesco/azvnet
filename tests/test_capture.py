from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from azvnet import non_azure_env
from azvnet.auth import AzvnetError, require_capture
from azvnet.tofu import Identity, configuration_bundle, guest_script

CANARY = "synthetic-a06-sensitive-output"
CHILD = r"""
import json
import sys
from pathlib import Path
from azvnet import AzureSession, AzvnetError, Bootstrap, Identity, VnetTofu

root, route, capture, arguments = json.loads(sys.argv[1])
settings = dict(tenant_id="tenant", subscription_id="subscription", client_id="client")
try:
    if route == "local":
        with AzureSession(**settings) as session:
            result = session.local_tofu(*arguments, workdir=Path(root), capture=capture)
    else:
        with VnetTofu(
            **settings, workdir=Path(root), config_files=["must-not-be-bundled.tf"],
            identity=Identity("/subscriptions/subscription/identity", "identity-client"),
            state_group="state", state_vnet="vnet", state_endpoint="example.invalid",
            bootstrap=Bootstrap("region", "subnet", "image", "size"), tofu_version="1.12.1",
        ) as engine:
            result = engine.run(*arguments, capture=capture)
    if capture:
        print(json.dumps({"captured_canary": "synthetic-a06-sensitive-output" in result.stdout + result.stderr}))
except AzvnetError as error:
    print(str(error), file=sys.stderr)
    raise SystemExit(17)
"""


class CaptureProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory()
        cls.root = Path(cls.scratch.name)
        cls.env = {**non_azure_env(), "ARM_CLIENT_SECRET": "synthetic-auth-only"}
        for key in list(cls.env):
            if key.startswith("TF_CLI_ARGS"):
                del cls.env[key]
        (cls.root / "main.tf").write_text(
            f'output "secret" {{\n value = "{CANARY}"\n sensitive = true\n}}\n'
            'output "public" { value = "safe-output" }\n'
        )
        for arguments in (["init", "-backend=false"], ["apply", "-auto-approve"]):
            subprocess.run(
                ["tofu", *arguments],
                cwd=cls.root,
                env=cls.env,
                capture_output=True,
                check=True,
            )

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def native(self, arguments):
        return subprocess.run(
            ["tofu", *arguments],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=True,
        )

    def child(self, arguments, *, route="local", capture=False):
        return subprocess.run(
            [
                os.sys.executable,
                "-c",
                CHILD,
                json.dumps([str(self.root), route, capture, arguments]),
            ],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
        )

    def assert_guarded(self, arguments):
        for route in ("local", "remote"):
            with self.subTest(route=route):
                result = self.child(arguments, route=route)
                self.assertEqual(result.returncode, 17, result.stderr)
                self.assertIn("capture=True", result.stderr)
                self.assertNotIn(CANARY, result.stdout + result.stderr)
        captured = self.child(arguments, capture=True)
        self.assertEqual(captured.returncode, 0, captured.stderr)
        self.assertTrue(json.loads(captured.stdout)["captured_canary"])
        self.assertNotIn(CANARY, captured.stdout + captured.stderr)

    def test_native_boolean_aliases_exports_and_explicit_capture(self):
        cases = []
        for verb, flag, tail in (
            ("output", "json", []),
            ("output", "raw", ["secret"]),
            ("show", "json", []),
            ("output", "show-sensitive", []),
            ("show", "show-sensitive", []),
        ):
            for prefix in ("-", "--"):
                for suffix in ("", "=true", "=1", "=t", "=T", "=TRUE", "=True"):
                    cases.append([verb, prefix + flag + suffix, *tail])
        cases.extend(
            [
                ["output", "secret"],
                ["output", "--", "secret"],
                ["output", "-no-color", "secret"],
                ["output", "-state", str(self.root / "terraform.tfstate"), "secret"],
                ["output", "--state=" + str(self.root / "terraform.tfstate"), "secret"],
                ["state", "pull"],
                ["output", "-json-into=/dev/stdout"],
                ["show", "--json-into=/dev/stderr"],
                [f"-chdir={self.root}", "output", "secret"],
                [f"-chdir={self.root}", "show", "--json=true"],
                [f"-chdir={self.root}", "state", "pull"],
            ]
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                native = self.native(arguments)
                self.assertIn(CANARY, native.stdout + native.stderr)
                self.assert_guarded(arguments)

    def test_safe_listing_and_false_boolean_forms_stay_safe(self):
        cases = [["output"], ["show"], ["output", "--"]]
        for verb, flag in (
            ("output", "json"),
            ("output", "raw"),
            ("show", "json"),
            ("output", "show-sensitive"),
            ("show", "show-sensitive"),
        ):
            for prefix in ("-", "--"):
                for value in ("false", "0", "f", "F", "FALSE", "False"):
                    cases.append([verb, prefix + flag + "=" + value])
        cases.extend(
            [
                ["output", "-state", str(self.root / "terraform.tfstate")],
                [f"-chdir={self.root}", "output", "-no-color"],
            ]
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                native = self.native(arguments)
                self.assertNotIn(CANARY, native.stdout + native.stderr)
                require_capture(arguments, False)
                result = self.child(arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("safe-output", result.stdout)
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_false_flags_cannot_hide_named_output(self):
        for arguments in (
            ["output", "--json=false", "secret"],
            ["output", "-raw=0", "secret"],
            ["output", "-show-sensitive=false", "secret"],
        ):
            with self.subTest(arguments=arguments):
                self.assertIn(CANARY, self.native(arguments).stdout)
                self.assert_guarded(arguments)

    def test_unsupported_global_forms_fail_before_execution(self):
        for arguments in (
            ["-chdir", str(self.root), "output", "secret"],
            ["--chdir=" + str(self.root), "output", "secret"],
            ["-help", "output", "secret"],
        ):
            for route in ("local", "remote"):
                for capture in (False, True):
                    result = self.child(arguments, route=route, capture=capture)
                    self.assertEqual(result.returncode, 17, result.stderr)
                    self.assertIn("unsupported OpenTofu global", result.stderr)
        result = self.child(
            [f"-chdir={self.root}", "output", "secret"], route="remote", capture=True
        )
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertIn("dedicated API", result.stderr)

    def test_output_unknown_options_fail_closed(self):
        for arguments in (
            ["output", "-unknown"],
            ["output", "-state"],
            ["output", "-json=invalid"],
        ):
            with self.assertRaises(AzvnetError):
                require_capture(arguments, False)

    def test_captured_generated_guest_output_uses_actual_state(self):
        version = json.loads(self.native(["version", "-json"]).stdout)[
            "terraform_version"
        ]
        for arguments in (
            ["output", "--json=true"],
            ["output", "-raw=true", "secret"],
            ["output", "secret"],
        ):
            require_capture(arguments, True)
            script = guest_script(
                bundle=configuration_bundle(self.root, ["main.tf"]),
                arguments=arguments,
                variables={},
                files={
                    "terraform.tfstate": (self.root / "terraform.tfstate").read_bytes()
                },
                tenant_id="tenant",
                subscription_id="subscription",
                identity=Identity("/identity", "client"),
                tofu_version=version,
            )
            result = subprocess.run(
                ["bash"],
                input=script,
                text=True,
                env=self.env,
                capture_output=True,
                check=True,
            )
            self.assertIn(CANARY, result.stdout)


if __name__ == "__main__":
    unittest.main()
