from __future__ import annotations

import base64
from contextlib import contextmanager
import json
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator

from .auth import AzureSession, AzvnetError


@contextmanager
def cleanup_after(action: Callable[[], object]) -> Iterator[None]:
    """Cleanup failures fail success, but annotate rather than replace a primary failure."""
    primary: BaseException | None = None
    try:
        yield
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            action()
        except Exception as error:
            if primary is None:
                raise
            primary.add_note(f"Cleanup also failed: {error}")
            print(f"Cleanup also failed: {error}", file=sys.stderr)


def completion_script(script: str, token: str, *, windows: bool = False) -> str:
    if not token.isalnum():
        raise ValueError("completion token must be alphanumeric")
    if windows:
        return (
            "$ErrorActionPreference = 'Stop'\n"
            "$global:LASTEXITCODE = 0\n"
            "& {\n" + script + "\n}\n"
            'if ($LASTEXITCODE -ne 0) { throw "Native command failed: $LASTEXITCODE" }\n'
            f"Write-Output '{token}'\n"
        )
    return (
        "set -eu\n"
        f"/bin/bash -seuo pipefail <<'{token}BODY'\n"
        + script
        + f"\n{token}BODY\n"
        + f"printf '\\n%s\\n' '{token}'\n"
    )


def parse_completion(
    result: subprocess.CompletedProcess[str], token: str
) -> tuple[str, str]:
    def failure(reason: str) -> AzvnetError:
        print(result.stdout or "", end="", file=sys.stderr)
        print(result.stderr or "", end="", file=sys.stderr)
        return AzvnetError(f"Azure Run Command failed: {reason}")

    if result.returncode:
        raise failure(f"CLI exit {result.returncode}")
    try:
        values = json.loads(result.stdout)["value"]
    except (ValueError, KeyError, TypeError) as error:
        raise failure("invalid ARM response") from error
    if not isinstance(values, list) or not values:
        raise failure("missing ARM status")
    stdout = None
    stderr = ""
    for value in values:
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("code"), str)
            or not isinstance(value.get("level"), str)
            or value["code"].lower() != "provisioningstate/succeeded"
            or value["level"].lower() != "info"
        ):
            raise failure("ARM operation did not succeed")
        message = value.get("message", "")
        if not isinstance(message, str):
            raise failure("invalid message")
        if message.count("[stdout]") != 1 or message.count("[stderr]") != 1:
            raise failure("missing, truncated, or ambiguous stream wrappers")
        _, body = message.split("[stdout]", 1)
        if "[stderr]" not in body or stdout is not None:
            raise failure("ambiguous stdout")
        stdout, stderr = body.split("[stderr]", 1)
    if stdout is None:
        raise failure("missing stdout")
    lines = stdout.strip("\r\n").splitlines()
    if not lines or lines[-1] != token or lines.count(token) != 1:
        raise failure("missing exact invocation-bound completion proof")
    output = "\n".join(lines[:-1]).rstrip("\r\n") + ("\n" if len(lines) > 1 else "")
    return output, stderr.lstrip("\r\n")


def encrypt_payload(certificate: str, payload: bytes) -> str:
    with tempfile.TemporaryDirectory(prefix="azvnet-encrypt-") as scratch:
        cert = Path(scratch) / "recipient.pem"
        cert.write_text(certificate, encoding="ascii")
        result = subprocess.run(
            [
                "openssl",
                "cms",
                "-encrypt",
                "-binary",
                "-aes256",
                "-outform",
                "DER",
                str(cert),
            ],
            input=payload,
            capture_output=True,
            check=True,
        )
        return base64.b64encode(result.stdout).decode("ascii")


def linux_envelope(directory: str, ciphertext: str) -> str:
    path = shlex.quote(directory)
    return f"""set -euo pipefail
directory={path}
trap 'rm -rf -- "$directory"' EXIT
cd "$directory"
printf %s {shlex.quote(ciphertext)} | base64 -d > payload.cms
openssl cms -decrypt -binary -inform DER -in payload.cms -recip cert.pem -inkey key.pem -out payload.sh
chmod 600 payload.sh
/bin/bash -euo pipefail payload.sh
"""


def linux_key_setup(directory: str) -> str:
    return f"""umask 077
mkdir {shlex.quote(directory)}
cd {shlex.quote(directory)}
if ! openssl req -x509 -newkey rsa:3072 -nodes -keyout key.pem -out cert.pem -subj /CN=azvnet -days 1 2>keygen.log; then
  cat keygen.log >&2
  exit 1
fi
cat cert.pem
"""


class Remote:
    def __init__(self, session: AzureSession):
        self.session = session

    def run(
        self,
        group: str,
        name: str,
        script: str,
        *,
        windows: bool = False,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        """Run a non-sensitive script. Use sealed() for secrets, state or configuration."""
        token = "AZVNET" + secrets.token_hex(24)
        with tempfile.TemporaryDirectory(prefix="azvnet-command-") as scratch:
            path = Path(scratch) / ("command.ps1" if windows else "command.sh")
            path.touch(mode=0o600)
            path.write_text(
                completion_script(script, token, windows=windows), encoding="utf-8"
            )
            result = self.session.run(
                "vm",
                "run-command",
                "invoke",
                "--resource-group",
                group,
                "--name",
                name,
                "--command-id",
                "RunPowerShellScript" if windows else "RunShellScript",
                "--scripts",
                f"@{path}",
                "--output",
                "json",
            )
        output, errors = parse_completion(result, token)
        if not capture:
            print(output, end="")
            print(errors, end="", file=sys.stderr)
        return subprocess.CompletedProcess(result.args, 0, output, errors)

    def sealed(
        self,
        group: str,
        name: str,
        script: str,
        *,
        windows: bool = False,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        """Encrypt to a fresh guest key; only ciphertext enters agent script storage."""
        nonce = secrets.token_hex(24)
        if windows:
            directory = rf"C:\ProgramData\azvnet-{nonce}"
            setup = rf"""
$d = '{directory}'
New-Item -ItemType Directory -Path $d | Out-Null
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {{
  $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $acl.AddAccessRule($rule)
}}
Set-Acl -Path $d -AclObject $acl
$cert = New-SelfSignedCertificate -Subject 'CN=azvnet-{nonce}' -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 3072 -KeyUsage KeyEncipherment -Type DocumentEncryptionCert
Set-Content -Path "$d\thumbprint" -Value $cert.Thumbprint
Write-Output '-----BEGIN CERTIFICATE-----'
Write-Output ([Convert]::ToBase64String($cert.RawData))
Write-Output '-----END CERTIFICATE-----'
"""
            cleanup = rf"""
$d = '{directory}'
Get-ChildItem Cert:\LocalMachine\My | Where-Object {{ $_.Subject -eq 'CN=azvnet-{nonce}' }} | Remove-Item -DeleteKey
if (Test-Path $d) {{ Remove-Item -LiteralPath $d -Recurse -Force }}
"""
        else:
            directory = f"/run/azvnet-{nonce}"
            setup = linux_key_setup(directory)
            cleanup = f"rm -rf -- {shlex.quote(directory)}"

        with cleanup_after(
            lambda: self.run(group, name, cleanup, windows=windows, capture=True)
        ):
            certificate = self.run(
                group, name, setup, windows=windows, capture=True
            ).stdout
            ciphertext = encrypt_payload(certificate, script.encode("utf-8"))
            if windows:
                execution = rf"""
$d = '{directory}'
Add-Type -AssemblyName System.Security
$cert = Get-Item ("Cert:\LocalMachine\My\" + (Get-Content "$d\thumbprint").Trim())
$cms = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms
$cms.Decode([Convert]::FromBase64String('{ciphertext}'))
$certs = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
[void]$certs.Add($cert)
$cms.Decrypt($certs)
$payload = [Text.Encoding]::UTF8.GetString($cms.ContentInfo.Content)
$executionFailure = $null
try {{
  & ([ScriptBlock]::Create($payload))
}} catch {{
  $executionFailure = $_
  throw
}} finally {{
  try {{
    Remove-Item ("Cert:\LocalMachine\My\" + $cert.Thumbprint) -DeleteKey
    Remove-Item -LiteralPath $d -Recurse -Force
  }} catch {{
    if ($null -eq $executionFailure) {{ throw }}
    Write-Warning "Cleanup also failed: $_"
  }}
}}
"""
            else:
                execution = linux_envelope(directory, ciphertext)
            return self.run(group, name, execution, windows=windows, capture=capture)
