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

from .auth import AzureSession, AzvnetError, non_azure_env

MAX_OUTPUT_BYTES = 8 * 1024 * 1024
OUTPUT_CHUNK_SIZE = 2048


class RemoteExecutionError(AzvnetError):
    """Guest failure with decrypted diagnostics available without logging them."""

    def __init__(self, returncode: int, stdout: str, stderr: str):
        super().__init__(
            f"sealed guest exited {returncode}; inspect exception.stdout/stderr privately"
        )
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


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
            "$transcript = Join-Path $env:TEMP ('azvnet-transcript-' + [Guid]::NewGuid().ToString('N'))\n"
            "New-Item -ItemType Directory -Path $transcript | Out-Null\n"
            "try {\n"
            "& {\n" + script + '\n} 1> "$transcript\\stdout" 2> "$transcript\\stderr"\n'
            'if ($LASTEXITCODE -ne 0) { throw "Native command failed: $LASTEXITCODE" }\n'
            '$document = @{ stdout=[IO.File]::ReadAllText("$transcript\\stdout"); stderr=[IO.File]::ReadAllText("$transcript\\stderr") } | ConvertTo-Json -Compress\n'
            "Write-Output ('AZVNETSTREAM ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($document)))\n"
            f"Write-Output '{token}'\n"
            "} catch {\n"
            "  foreach ($stream in @('stdout','stderr')) {\n"
            "    $path = Join-Path $transcript $stream\n"
            "    if (Test-Path -LiteralPath $path) { [Console]::Error.Write([IO.File]::ReadAllText($path)) }\n"
            "  }\n"
            "  throw\n"
            "} finally { Remove-Item -LiteralPath $transcript -Recurse -Force }\n"
        )
    return (
        "set -eu\n"
        "umask 077\n"
        "transcript=$(mktemp -d)\n"
        """trap 'rm -rf -- "$transcript"' EXIT\n"""
        "status=0\n"
        f"""/bin/bash -seuo pipefail >"$transcript/stdout" 2>"$transcript/stderr" <<'{token}BODY' || status=$?\n"""
        + script
        + f"\n{token}BODY\n"
        + """if [ "$status" -ne 0 ]; then
  cat "$transcript/stdout"
  cat "$transcript/stderr" >&2
  exit "$status"
fi
python3 - "$transcript" <<'PY'
import base64, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
document = {key: (root / key).read_text(errors="replace") for key in ("stdout", "stderr")}
print("AZVNETSTREAM " + base64.b64encode(json.dumps(document).encode()).decode())
PY
"""
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
    components: dict[str, str] = {}
    for value in values:
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("code"), str)
            or not isinstance(value.get("level"), str)
            or value["level"].lower() != "info"
        ):
            raise failure("ARM operation did not succeed")
        message = value.get("message", "")
        if not isinstance(message, str):
            raise failure("invalid message")
        code = value["code"].lower()
        if code in {
            "componentstatus/stdout/succeeded",
            "componentstatus/stderr/succeeded",
        }:
            stream = code.split("/")[1]
            if stdout is not None or stream in components:
                raise failure("duplicate or mixed stream statuses")
            components[stream] = message
            continue
        if code != "provisioningstate/succeeded" or components:
            raise failure("ARM operation did not succeed or mixed stream statuses")
        if message.count("[stdout]") != 1 or message.count("[stderr]") != 1:
            raise failure("missing, truncated, or ambiguous stream wrappers")
        _, body = message.split("[stdout]", 1)
        if "[stderr]" not in body or stdout is not None:
            raise failure("ambiguous stdout")
        stdout, stderr = body.split("[stderr]", 1)
    if components:
        if set(components) != {"stdout", "stderr"}:
            raise failure("missing component stream status")
        stdout, stderr = components["stdout"], components["stderr"]
    if stdout is None:
        raise failure("missing stdout")
    lines = stdout.strip("\r\n").splitlines()
    if not lines or lines[-1] != token or lines.count(token) != 1:
        raise failure("missing exact invocation-bound completion proof")
    frames = [line for line in lines[:-1] if line]
    if len(frames) != 1 or not frames[0].startswith("AZVNETSTREAM "):
        raise failure("missing or truncated output frame")
    try:
        document = json.loads(base64.b64decode(frames[0][13:], validate=True))
        if not isinstance(document["stdout"], str) or not isinstance(
            document["stderr"], str
        ):
            raise ValueError("invalid stream types")
    except (ValueError, KeyError, TypeError) as error:
        raise failure("invalid or truncated output frame") from error
    return document["stdout"], document["stderr"] + stderr.lstrip("\r\n")


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
            env=non_azure_env(),
            capture_output=True,
            check=True,
        )
        return base64.b64encode(result.stdout).decode("ascii")


def linux_envelope(
    directory: str,
    ciphertext: str,
    output_certificate: str | None = None,
) -> str:
    path = shlex.quote(directory)
    cleanup = (
        "rm -f -- "
        + " ".join(
            f'"$directory/{name}"'
            for name in (
                "key.pem",
                "cert.pem",
                "payload.cms",
                "payload.sh",
                "stdout",
                "stderr",
                "response.json",
                "caller.pem",
            )
        )
        if output_certificate is not None
        else """rm -rf -- "$directory" """
    )
    script = f"""set -euo pipefail
directory={path}
trap '{cleanup}' EXIT
cd "$directory"
printf %s {shlex.quote(ciphertext)} | base64 -d > payload.cms
openssl cms -decrypt -binary -inform DER -in payload.cms -recip cert.pem -inkey key.pem -out payload.sh
chmod 600 payload.sh
"""
    if output_certificate is None:
        return (
            script
            + """/bin/bash -euo pipefail payload.sh
"""
        )
    encoded_cert = base64.b64encode(output_certificate.encode()).decode()
    return (
        script
        + f"""printf %s {encoded_cert} | base64 -d > caller.pem
status=0
/bin/bash -euo pipefail payload.sh >stdout 2>stderr || status=$?
python3 - "$status" <<'PY'
import json, pathlib, sys
out, err = pathlib.Path("stdout"), pathlib.Path("stderr")
if out.stat().st_size + err.stat().st_size > {MAX_OUTPUT_BYTES}:
    raise SystemExit("sealed output exceeds the configured transport bound")
pathlib.Path("response.json").write_text(json.dumps({{
    "returncode": int(sys.argv[1]),
    "stdout": out.read_text(errors="replace"),
    "stderr": err.read_text(errors="replace"),
}}))
PY
openssl cms -encrypt -binary -aes256 -outform DER -in response.json -out response.cms caller.pem
base64 -w0 response.cms > response.b64
printf 'AZVNETOUTPUT %s\\n' "$(wc -c < response.b64)"
"""
    )


def decrypt_payload(directory: Path, ciphertext: str) -> tuple[int, str, str]:
    result = subprocess.run(
        [
            "openssl",
            "cms",
            "-decrypt",
            "-binary",
            "-inform",
            "DER",
            "-recip",
            str(directory / "cert.pem"),
            "-inkey",
            str(directory / "key.pem"),
        ],
        input=base64.b64decode(ciphertext, validate=True),
        env=non_azure_env(),
        capture_output=True,
        check=True,
    )
    document = json.loads(result.stdout)
    if (
        not isinstance(document.get("returncode"), int)
        or not isinstance(document.get("stdout"), str)
        or not isinstance(document.get("stderr"), str)
    ):
        raise AzvnetError("invalid sealed response")
    return document["returncode"], document["stdout"], document["stderr"]


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


def output_chunk_script(
    directory: str, offset: int, size: int, *, windows: bool
) -> str:
    if windows:
        return rf"Write-Output ([IO.File]::ReadAllText('{directory}\response.b64').Substring({offset},{size}))"
    return f"""python3 - <<'PY'
with open({directory + "/response.b64"!r}) as stream:
    stream.seek({offset})
    print(stream.read({size}), end="")
PY"""


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
        """Encrypt both script input and captured output with per-invocation keys."""
        with tempfile.TemporaryDirectory(prefix="azvnet-output-") as scratch:
            caller = Path(scratch)
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:3072",
                    "-nodes",
                    "-keyout",
                    str(caller / "key.pem"),
                    "-out",
                    str(caller / "cert.pem"),
                    "-subj",
                    "/CN=azvnet-output",
                    "-days",
                    "1",
                ],
                env=non_azure_env(),
                capture_output=True,
                check=True,
            )
            encrypted = self._sealed(
                group,
                name,
                script,
                windows=windows,
                output_certificate=(caller / "cert.pem").read_text(),
            )
            status, output, errors = decrypt_payload(caller, encrypted)
        if status:
            raise RemoteExecutionError(status, output, errors)
        if not capture:
            print(output, end="")
            print(errors, end="", file=sys.stderr)
        return subprocess.CompletedProcess(["sealed-run-command"], 0, output, errors)

    def _sealed(
        self,
        group: str,
        name: str,
        script: str,
        *,
        windows: bool,
        output_certificate: str,
    ) -> str:
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
$cert = New-SelfSignedCertificate -Subject 'CN=azvnet-{nonce}' -CertStoreLocation Cert:\LocalMachine\My -Provider 'Microsoft Software Key Storage Provider' -KeyAlgorithm RSA -KeyLength 3072 -KeyUsage KeyEncipherment -Type DocumentEncryptionCert
Set-Content -Path "$d\thumbprint" -Value $cert.Thumbprint
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
try {{
  $keyPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $rsa.Key.UniqueName
  if (-not (Test-Path -LiteralPath $keyPath)) {{ throw 'task certificate private key file not found' }}
  Set-Content -LiteralPath "$d\private-key-path" -Value $keyPath
}} finally {{ $rsa.Dispose() }}
Write-Output '-----BEGIN CERTIFICATE-----'
Write-Output ([Convert]::ToBase64String($cert.RawData))
Write-Output '-----END CERTIFICATE-----'
"""
            cleanup = rf"""
$d = '{directory}'
foreach ($cert in @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {{ $_.Subject -eq 'CN=azvnet-{nonce}' }})) {{
  Remove-Item -LiteralPath ("Cert:\LocalMachine\My\" + $cert.Thumbprint) -DeleteKey
}}
if (Test-Path -LiteralPath "$d\private-key-path") {{
  $keyPath = (Get-Content -LiteralPath "$d\private-key-path").Trim()
  if (Test-Path -LiteralPath $keyPath) {{ throw 'task certificate private key survived deletion' }}
}}
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
Set-Content -LiteralPath "$d\payload.ps1" -Encoding UTF8 -Value ("`$ErrorActionPreference = 'Stop'`n" + $payload + "`nif (`$LASTEXITCODE -ne 0) {{ exit `$LASTEXITCODE }}")
$executionFailure = $null
try {{
  $process = Start-Process powershell.exe -Wait -PassThru -ArgumentList @('-NoProfile','-NonInteractive','-File',"$d\payload.ps1") -RedirectStandardOutput "$d\stdout" -RedirectStandardError "$d\stderr"
  if ((Get-Item "$d\stdout").Length + (Get-Item "$d\stderr").Length -gt {MAX_OUTPUT_BYTES}) {{ throw 'sealed output exceeds the configured transport bound' }}
  $response = @{{ returncode = $process.ExitCode; stdout = [IO.File]::ReadAllText("$d\stdout"); stderr = [IO.File]::ReadAllText("$d\stderr") }} | ConvertTo-Json -Compress
  $recipientBytes = [Convert]::FromBase64String('{base64.b64encode(output_certificate.encode()).decode()}')
  $pem = [Text.Encoding]::ASCII.GetString($recipientBytes)
  $der = [Convert]::FromBase64String(($pem -replace '-----[^-]+-----','' -replace '\s',''))
  $recipient = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$der)
  $content = New-Object System.Security.Cryptography.Pkcs.ContentInfo(,[Text.Encoding]::UTF8.GetBytes($response))
  $algorithm = New-Object System.Security.Cryptography.Pkcs.AlgorithmIdentifier([System.Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.1.42'))
  $encrypted = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms($content,$algorithm)
  $encrypted.Encrypt((New-Object System.Security.Cryptography.Pkcs.CmsRecipient($recipient)))
  $encoded = [Convert]::ToBase64String($encrypted.Encode())
  [IO.File]::WriteAllText("$d\response.b64", $encoded)
  Write-Output "AZVNETOUTPUT $($encoded.Length)"
}} catch {{
  $executionFailure = $_
  throw
}} finally {{
  try {{
    Remove-Item ("Cert:\LocalMachine\My\" + $cert.Thumbprint) -DeleteKey
    Remove-Item -LiteralPath "$d\payload.ps1","$d\stdout","$d\stderr" -Force
  }} catch {{
    if ($null -eq $executionFailure) {{ throw }}
    Write-Warning "Cleanup also failed: $_"
  }}
}}
"""
            else:
                execution = linux_envelope(directory, ciphertext, output_certificate)
            manifest = (
                self.run(
                    group,
                    name,
                    execution,
                    windows=windows,
                    capture=True,
                )
                .stdout.strip()
                .split()
            )
            if (
                len(manifest) != 2
                or manifest[0] != "AZVNETOUTPUT"
                or not manifest[1].isdigit()
            ):
                raise AzvnetError("missing sealed output manifest")
            length = int(manifest[1])
            # JSON escaping and base64 can expand plaintext by up to eight times.
            if not 0 < length <= MAX_OUTPUT_BYTES * 8 + 16384:
                raise AzvnetError("sealed output length exceeds the retrieval bound")
            chunks = []
            for offset in range(0, length, OUTPUT_CHUNK_SIZE):
                size = min(OUTPUT_CHUNK_SIZE, length - offset)
                retrieval = output_chunk_script(
                    directory, offset, size, windows=windows
                )
                chunk = self.run(
                    group, name, retrieval, windows=windows, capture=True
                ).stdout.strip()
                if len(chunk) != size:
                    raise AzvnetError("sealed output chunk was truncated")
                chunks.append(chunk)
            return "".join(chunks)
