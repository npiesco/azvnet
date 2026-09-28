"""Explicitly authorized Windows transport acceptance; no fleet/registration mutation."""

from __future__ import annotations

import argparse
from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import secrets
import signal

from azvnet import AzureSession, AzvnetError, Remote, RemoteExecutionError


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--group", required=True)
    parser.add_argument("--vm", required=True)
    parser.add_argument(
        "--phase", choices=["plain", "sealed", "inspect"], required=True
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="reuse the cached Azure CLI user of AZURE_CONFIG_DIR instead of a service principal",
    )
    args = parser.parse_args()

    def timeout(signum, frame):
        raise TimeoutError("whole-job Windows acceptance watchdog")

    signal.signal(signal.SIGTERM, timeout)
    identity = {
        "tenant_id": os.environ["ARM_TENANT_ID"],
        "subscription_id": os.environ["ARM_SUBSCRIPTION_ID"],
    }
    if args.interactive:
        # The caller selects the cached CLI context explicitly; it is never guessed.
        ambient = Path(os.environ["AZURE_CONFIG_DIR"])
        session = AzureSession(**identity, interactive=True)
    else:
        session = AzureSession(**identity, client_id=os.environ["ARM_CLIENT_ID"])
    with session as azure:
        remote = Remote(azure)
        if args.phase == "plain":
            result = remote.run(
                args.group,
                args.vm,
                "Write-Output 'windows-success'",
                windows=True,
                capture=True,
            )
            assert result.stdout.strip() == "windows-success"
            print("PASS Windows Remote.run success", flush=True)
            for script in ("throw 'terminating-control'", "cmd.exe /d /c exit 27"):
                with redirect_stderr(io.StringIO()) as diagnostic:
                    try:
                        remote.run(
                            args.group, args.vm, script, windows=True, capture=True
                        )
                    except AzvnetError:
                        expected = (
                            "terminating-control"
                            if "throw" in script
                            else "Native command failed: 27"
                        )
                        assert expected in diagnostic.getvalue()
                    else:
                        raise AssertionError("Windows guest failure accepted")
            print(
                "PASS terminating PowerShell and native cmd.exe failure rejected",
                flush=True,
            )
            result = remote.run(
                args.group,
                args.vm,
                "Write-Output '[stdout]'; Write-Output '[stderr]'",
                windows=True,
                capture=True,
            )
            assert result.stdout.splitlines() == ["[stdout]", "[stderr]"]
            with redirect_stderr(io.StringIO()):
                try:
                    remote.run(
                        args.group,
                        args.vm,
                        "Write-Output ('x' * 16000)",
                        windows=True,
                        capture=True,
                    )
                except AzvnetError:
                    pass
                else:
                    raise AssertionError("truncated Windows output accepted")
            print("PASS exact stream framing and truncation rejection", flush=True)
        elif args.phase == "sealed":
            canary = "azvnet-windows-canary-" + secrets.token_hex(20)
            result = remote.sealed(
                args.group,
                args.vm,
                f"[Console]::Out.Write('{canary}'); [Console]::Error.Write('{canary}-stderr')",
                windows=True,
                capture=True,
            )
            assert result.stdout == canary and result.stderr == canary + "-stderr"
            print("PASS Windows encrypted input and both output streams", flush=True)
            for body in ("cmd.exe /d /c exit 29", f"throw '{canary}'"):
                try:
                    remote.sealed(args.group, args.vm, body, windows=True, capture=True)
                except RemoteExecutionError as error:
                    assert error.returncode != 0
                    if "throw" in body:
                        assert canary in error.stderr
                    else:
                        assert error.returncode == 29
                    assert canary not in str(error)
                else:
                    raise AssertionError("sealed guest failure accepted")
            print(
                "PASS sealed native/PowerShell failure diagnostics stay private",
                flush=True,
            )
            output = remote.sealed(
                args.group,
                args.vm,
                "[Console]::Out.Write('abcdefgh' * 650)",
                windows=True,
                capture=True,
            ).stdout
            assert output == "abcdefgh" * 650
            print("PASS Windows encrypted multi-chunk return", flush=True)
        if args.phase in {"sealed", "inspect"}:
            canary = "azvnet-windows-canary-"
            scan = rf"""
$needle = '{canary}'
$roots = @('C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows', 'C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.RunCommandWindows')
$files = 0; $decoded = 0
foreach ($root in $roots) {{
  if (Test-Path $root) {{
    foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File) {{
      $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
      $buffer = New-Object IO.MemoryStream
      try {{ $stream.CopyTo($buffer); $bytes = $buffer.ToArray() }}
      finally {{ $buffer.Dispose(); $stream.Dispose() }}
      $texts = @([Text.Encoding]::UTF8.GetString($bytes), [Text.Encoding]::Unicode.GetString($bytes))
      $files++
      for ($depth=0; $depth -lt 3; $depth++) {{
        $next = @()
        foreach ($text in $texts) {{
          if ($text.Contains($needle)) {{ throw 'synthetic canary persisted in agent material' }}
          foreach ($match in [regex]::Matches($text, '[A-Za-z0-9+/=]{{32,}}')) {{
            try {{ $data = [Convert]::FromBase64String($match.Value) }} catch [FormatException] {{ continue }}
            $next += [Text.Encoding]::UTF8.GetString($data)
            $next += [Text.Encoding]::Unicode.GetString($data)
            $decoded++
          }}
        }}
        $texts = $next
      }}
    }}
  }}
}}
if ($files -eq 0) {{ throw 'Run Command directories were not inspected' }}
foreach ($process in Get-CimInstance Win32_Process) {{
  if ($process.CommandLine -and $process.CommandLine.Contains($needle)) {{ throw 'synthetic canary in process argv' }}
}}
Write-Output "canary scan passed: $files files, $decoded encoded values"
"""
            try:
                result = remote.sealed(
                    args.group, args.vm, scan, windows=True, capture=True
                )
            except RemoteExecutionError as error:
                diagnostic = error.stderr
                secret = os.environ.get("ARM_CLIENT_SECRET")
                if secret:
                    diagnostic = diagnostic.replace(secret, "[redacted]")
                print(diagnostic.replace(canary, "[synthetic-canary]"), flush=True)
                raise
            assert "canary scan passed:" in result.stdout
            print(result.stdout.strip(), flush=True)
        cleanup = r"""
$directories = @(Get-ChildItem C:\ProgramData -Directory -Filter 'azvnet-*')
$certificates = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like 'CN=azvnet-*' })
if ($directories.Count -ne 0 -or $certificates.Count -ne 0) { throw 'task transport artifacts remain' }
$transcripts = @(Get-ChildItem -LiteralPath $env:TEMP -Directory -Filter 'azvnet-transcript-*' | Where-Object { $_.FullName -ne $transcript })
if ($transcripts.Count -ne 0) { throw 'task transcript directories remain' }
Write-Output 'no task directories or certificates remain'
"""
        assert (
            "no task directories"
            in remote.run(
                args.group,
                args.vm,
                cleanup,
                windows=True,
                capture=True,
            ).stdout
        )
        cache = Path(azure.env["AZURE_CONFIG_DIR"])
    if args.interactive:
        # An interactive session reuses the caller's cache; it must survive intact.
        assert cache == ambient and cache.is_dir()
        print("PASS task certificate/directory cleanup; cached CLI context kept", flush=True)
        return
    assert not cache.exists()
    print("PASS task certificate/directory and private CLI cache cleanup", flush=True)


if __name__ == "__main__":
    main()
