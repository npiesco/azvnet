from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence

CLI_STDIN_PROGRAM = (
    "import json,sys; from azure.cli.core import get_default_cli; "
    "sys.exit(get_default_cli().invoke(json.load(sys.stdin)))"
)


class AzvnetError(RuntimeError):
    """An operation did not complete successfully."""


def require_capture(arguments: Sequence[str], capture: bool) -> None:
    exports_state = list(arguments[:2]) == ["state", "pull"]
    exports_values = (
        bool(arguments)
        and arguments[0] in {"show", "output"}
        and any(flag in arguments for flag in ("-json", "-raw"))
    )
    if not capture and (exports_state or exports_values):
        raise AzvnetError(
            "state/raw output can contain secrets; capture=True is required"
        )


def checked(
    args: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        env=env,
        cwd=cwd,
        text=True,
        capture_output=capture,
        check=False,
    )
    if result.returncode:
        if capture:
            print(result.stdout or "", end="", file=sys.stderr)
            print(result.stderr or "", end="", file=sys.stderr)
        raise subprocess.CalledProcessError(
            result.returncode,
            args,
            result.stdout,
            result.stderr,
        )
    return result


def private_text(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, encoding="utf-8") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise AzvnetError(f"{path}: must be a regular mode-0600 file")
        if metadata.st_uid != os.getuid():
            raise AzvnetError(f"{path}: must be owned by the current user")
        return stream.read()


def credentials(
    *,
    tenant_id: str,
    subscription_id: str,
    client_id: str | None,
    environ: Mapping[str, str],
    credential_file: Path | None = None,
    interactive: bool = False,
) -> dict[str, str]:
    expected = {"ARM_TENANT_ID": tenant_id, "ARM_SUBSCRIPTION_ID": subscription_id}
    if client_id:
        expected["ARM_CLIENT_ID"] = client_id
    for key, value in expected.items():
        if environ.get(key) and environ[key].lower() != value.lower():
            raise AzvnetError(f"{key} conflicts with the configured identity")
    secret = environ.get("ARM_CLIENT_SECRET")
    selected_client = client_id or environ.get("ARM_CLIENT_ID")
    if not secret and credential_file is not None:
        text = private_text(credential_file)
        fields = {}
        for label, key in (
            ("Tenant", "ARM_TENANT_ID"),
            ("Client\\s*ID", "ARM_CLIENT_ID"),
            ("Secret", "ARM_CLIENT_SECRET"),
            ("Subscription", "ARM_SUBSCRIPTION_ID"),
        ):
            matches = re.findall(rf"^{label}\s*:\s*(\S+)\s*$", text, re.I | re.M)
            if len(matches) > 1:
                raise AzvnetError(f"{credential_file}: duplicate credential field")
            if matches:
                fields[key] = matches[0]
        if not all(
            key in fields
            for key in ("ARM_TENANT_ID", "ARM_CLIENT_ID", "ARM_CLIENT_SECRET")
        ):
            raise AzvnetError(f"{credential_file}: expected Tenant/Client ID/Secret")
        for key, value in expected.items():
            if key in fields and fields[key].lower() != value.lower():
                raise AzvnetError(
                    f"{credential_file}: {key} conflicts with configuration"
                )
        if (
            selected_client
            and selected_client.lower() != fields["ARM_CLIENT_ID"].lower()
        ):
            raise AzvnetError("credential file conflicts with ARM_CLIENT_ID")
        selected_client, secret = fields["ARM_CLIENT_ID"], fields["ARM_CLIENT_SECRET"]
    if secret:
        if not selected_client:
            raise AzvnetError(
                "service-principal authentication requires client_id or ARM_CLIENT_ID"
            )
        return {
            **expected,
            "ARM_CLIENT_ID": selected_client,
            "ARM_CLIENT_SECRET": secret,
            "ARM_USE_CLI": "false",
            "ARM_USE_MSI": "false",
        }
    if not interactive:
        raise AzvnetError(
            "set ARM_CLIENT_SECRET or configure a mode-0600 credential file"
        )
    if selected_client:
        raise AzvnetError(
            "client_id was supplied without service-principal credentials"
        )
    return {**expected, "ARM_USE_CLI": "true", "ARM_USE_MSI": "false"}


class AzureSession:
    """Process-scoped authentication; cached interactive accounts are opt-in."""

    def __init__(
        self,
        *,
        tenant_id: str,
        subscription_id: str,
        client_id: str | None = None,
        credential_file: Path | None = None,
        interactive: bool = False,
        cli_python: Path | None = None,
        environ: Mapping[str, str] | None = None,
    ):
        if not tenant_id or not subscription_id:
            raise ValueError("tenant_id and subscription_id are required")
        self.tenant_id, self.subscription_id = tenant_id, subscription_id
        self.env = dict(os.environ if environ is None else environ)
        self.env.update(
            credentials(
                tenant_id=tenant_id,
                subscription_id=subscription_id,
                client_id=client_id,
                environ=self.env,
                credential_file=credential_file,
                interactive=interactive,
            )
        )
        self.cli_python = cli_python or (
            Path(self.env["AZVNET_CLI_PYTHON"])
            if self.env.get("AZVNET_CLI_PYTHON")
            else None
        )
        self._directory: tempfile.TemporaryDirectory[str] | None = None
        self._authenticated = False

    def __enter__(self) -> AzureSession:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._directory:
            self._directory.cleanup()
            self._directory = None
        self._authenticated = False

    def login(self) -> None:
        if self._authenticated:
            return
        if self.env.get("ARM_CLIENT_SECRET"):
            if self.cli_python is None:
                raise AzvnetError(
                    "set AZVNET_CLI_PYTHON to the Python interpreter containing azure.cli "
                    "(or pass cli_python); login secrets are sent over stdin, never argv"
                )
            self._directory = tempfile.TemporaryDirectory(prefix="azvnet-azure-")
            self.env["AZURE_CONFIG_DIR"] = self._directory.name
            # Invoke the installed Azure CLI, but deliver its arguments over a pipe.
            # sys.argv within Python is not the OS process command line.
            args = [
                "login",
                "--service-principal",
                "--username",
                self.env["ARM_CLIENT_ID"],
                "--password",
                self.env["ARM_CLIENT_SECRET"],
                "--tenant",
                self.tenant_id,
                "--only-show-errors",
                "--output",
                "none",
            ]
            result = subprocess.run(
                [str(self.cli_python), "-c", CLI_STDIN_PROGRAM],
                input=json.dumps(args),
                env=self.env,
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode:
                detail = (result.stderr or result.stdout).replace(
                    self.env["ARM_CLIENT_SECRET"], "[redacted]"
                )
                raise AzvnetError(f"Azure CLI login failed: {detail.strip()}")
        account = self._invoke(
            [
                "account",
                "show",
                "--subscription",
                self.subscription_id,
                "--output",
                "json",
            ],
        )
        document = json.loads(account.stdout)
        if (document["id"].lower(), document["tenantId"].lower()) != (
            self.subscription_id.lower(),
            self.tenant_id.lower(),
        ):
            raise AzvnetError(
                "Azure CLI account conflicts with configured tenant/subscription"
            )
        if self.env.get("ARM_CLIENT_SECRET"):
            user = document["user"]
            if (
                user["type"].lower() != "serviceprincipal"
                or user["name"].lower() != self.env["ARM_CLIENT_ID"].lower()
            ):
                raise AzvnetError(
                    "Azure CLI service principal conflicts with configured client"
                )
        elif document["user"]["type"].lower() != "user":
            raise AzvnetError("interactive mode requires a cached user account")
        self._authenticated = True

    def _invoke(self, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return checked(
            ["az", *arguments, "--only-show-errors"],
            env=self.env,
            capture=True,
        )

    def run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        args = list(arguments)
        specified = False
        for position, argument in enumerate(args):
            if argument in {"--subscription", "-s"} or argument.startswith(
                "--subscription="
            ):
                selected = (
                    argument.split("=", 1)[1]
                    if "=" in argument
                    else (args[position + 1] if position + 1 < len(args) else "")
                )
                if selected.lower() != self.subscription_id.lower():
                    raise AzvnetError(
                        "Azure invocation conflicts with configured subscription"
                    )
                specified = True
        if not specified:
            args += ["--subscription", self.subscription_id]
        self.login()
        return self._invoke(args)

    def json(self, *arguments: str):
        return json.loads(self.run(*arguments, "--output", "json").stdout)

    def group_exists(self, name: str) -> bool:
        value = self.run(
            "group", "exists", "--name", name, "--output", "tsv"
        ).stdout.strip()
        if value not in {"true", "false"}:
            raise AzvnetError("Azure group exists returned neither true nor false")
        return value == "true"

    def local_tofu(
        self,
        *arguments: str,
        workdir: Path,
        env: Mapping[str, str] | None = None,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        if not arguments:
            raise ValueError("an OpenTofu command is required")
        require_capture(arguments, capture)
        environment = {**self.env, **(env or {})}
        for key in (
            "ARM_TENANT_ID",
            "ARM_SUBSCRIPTION_ID",
            "ARM_CLIENT_ID",
            "ARM_CLIENT_SECRET",
            "ARM_USE_CLI",
            "ARM_USE_MSI",
        ):
            if key in self.env and environment.get(key) != self.env[key]:
                raise AzvnetError(f"{key} conflicts with session")
        if not self.env.get("ARM_CLIENT_SECRET") and arguments[0] not in {
            "init",
            "fmt",
            "validate",
            "version",
        }:
            self.login()
        return checked(
            ["tofu", *arguments], cwd=workdir, env=environment, capture=capture
        )
