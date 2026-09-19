"""Opt-in live proofs; every target and evidence path is supplied by the operator."""

from __future__ import annotations

import argparse
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
import hashlib
import io
import json
import os
import re
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile

from azvnet import (
    AzureSession,
    AzvnetError,
    Bootstrap,
    Host,
    Identity,
    Remote,
    VnetTofu,
)
from azvnet.remote import RemoteExecutionError


def session(**overrides) -> AzureSession:
    return AzureSession(
        tenant_id=os.environ["ARM_TENANT_ID"],
        subscription_id=os.environ["ARM_SUBSCRIPTION_ID"],
        client_id=os.environ["ARM_CLIENT_ID"],
        environ={**os.environ, **overrides},
    )


def ambient_fingerprint() -> dict[str, str]:
    root = Path(os.environ.get("AZURE_CONFIG_DIR", str(Path.home() / ".azure")))
    return {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in (
            "azureProfile.json",
            "msal_token_cache.json",
            "msal_token_cache.bin",
            "service_principal_entries.json",
            "service_principal_entries.bin",
            "config",
        )
        if (root / name).is_file()
    }


def authentication() -> None:
    before = ambient_fingerprint()
    environment = dict(os.environ)
    with session() as azure:
        azure.login()
        directory = Path(azure.env["AZURE_CONFIG_DIR"])
        assert directory.is_relative_to(Path(tempfile.gettempdir()))
        assert directory.stat().st_mode & 0o777 == 0o700
        account = azure.json("account", "show")
        assert account["id"].lower() == azure.subscription_id.lower()
        assert account["tenantId"].lower() == azure.tenant_id.lower()
        assert account["user"]["name"].lower() == azure.env["ARM_CLIENT_ID"].lower()
        for log in directory.rglob("*.log"):
            assert azure.env["ARM_CLIENT_SECRET"].encode() not in log.read_bytes(), (
                "credential in CLI log"
            )
        with redirect_stderr(io.StringIO()):
            try:
                azure.run("azvnet-deliberately-invalid-command")
            except subprocess.CalledProcessError as error:
                assert error.returncode != 0 and error.stderr
            else:
                raise AssertionError("failed CLI command returned success")
    assert not directory.exists()
    assert before == ambient_fingerprint()
    assert environment == dict(os.environ)
    invalid = "azvnet-invalid-" + secrets.token_hex(16)
    with session(ARM_CLIENT_SECRET=invalid) as azure:
        try:
            azure.login()
        except AzvnetError as error:
            assert "login failed" in str(error)
            assert invalid not in str(error)
            assert os.environ["ARM_CLIENT_SECRET"] not in str(error)
            assert "AADSTS" in str(error)
            codes = sorted(set(re.findall(r"AADSTS\d+", str(error))))
            print(
                "PASS invalid-secret rejection:",
                ",".join(codes),
                "(credential redacted)",
            )
        else:
            raise AssertionError("invalid secret authenticated")
        invalid_cache = Path(azure.env["AZURE_CONFIG_DIR"])
        for log in invalid_cache.rglob("*.log"):
            assert invalid.encode() not in log.read_bytes(), (
                "invalid credential in CLI log"
            )
    assert not invalid_cache.exists()
    assert before == ambient_fingerprint()
    print(
        "PASS cold SP identity binding, unchanged ambient context/environment, cache cleanup, checked CLI failure"
    )


def remote_commands(group: str, vm: str) -> None:
    with session() as azure:
        remote = Remote(azure)
        assert (
            remote.run(group, vm, "printf 'remote-success\\n'", capture=True).stdout
            == "remote-success\n"
        )
        print("PASS real Linux Run Command success", flush=True)
        with redirect_stderr(io.StringIO()) as diagnostic:
            try:
                remote.run(group, vm, "echo guest-failure >&2; exit 19", capture=True)
            except AzvnetError:
                assert "guest-failure" in diagnostic.getvalue()
                assert "ProvisioningState/succeeded" in diagnostic.getvalue()
            else:
                raise AssertionError("ARM success concealed guest failure")
        print("PASS guest failure despite ARM success", flush=True)
        try:
            with redirect_stderr(io.StringIO()):
                remote.run(
                    group,
                    vm,
                    "python3 -c 'print(\"x\" * 16000)'",
                    capture=True,
                ).stdout
        except AzvnetError:
            print(
                "PASS long output rejected when Azure truncates proof/wrappers",
                flush=True,
            )
        else:
            raise AssertionError("truncated Run Command output was accepted")
        canary = "azvnet-canary-" + secrets.token_hex(24)
        result = remote.sealed(group, vm, f"printf '%s\\n' '{canary}'", capture=True)
        assert result.stdout.strip() == canary
        try:
            remote.sealed(group, vm, f"echo '{canary}' >&2; exit 31", capture=True)
        except RemoteExecutionError as error:
            assert error.returncode == 31 and canary in error.stderr
            assert canary not in str(error)
        else:
            raise AssertionError("sealed failure became success")
        # The canary is delivered encrypted. The scan itself must not put it in
        # a retained script or process argument.
        scan = f"""python3 - <<'PY'
from pathlib import Path
needle = {canary.encode()!r}
for path in Path('/var/lib/waagent').rglob('*'):
    if path.is_file() and not path.is_symlink():
        assert needle not in path.read_bytes(), 'canary in retained agent file'
for path in Path('/proc').glob('[0-9]*/cmdline'):
    try:
        content = path.read_bytes()
    except FileNotFoundError:
        continue
    assert needle not in content, 'canary in process arguments'
print('canary absent from retained scripts/output and process arguments')
PY"""
        assert "canary absent" in remote.sealed(group, vm, scan, capture=True).stdout
        print(
            "PASS sealed canary input/output, encrypted error diagnostics, agent/process scan",
            flush=True,
        )

        def concurrent(label: str) -> tuple[str, str]:
            try:
                return label, remote.sealed(
                    group, vm, f"printf '{label}\\n'", capture=True
                ).stdout.strip()
            except subprocess.CalledProcessError as error:
                if "Conflict" in (error.stderr or "") or "in progress" in (
                    error.stderr or ""
                ):
                    return label, "explicit-azure-conflict"
                raise

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(concurrent, ["isolation-a", "isolation-b"]))
        assert all(
            value in {label, "explicit-azure-conflict"} for label, value in outcomes
        )
        assert any(value == label for label, value in outcomes)
        print("PASS concurrent invocation isolation:", json.dumps(outcomes), flush=True)
        assert (
            remote.run(
                group,
                vm,
                "find /run -maxdepth 1 -name 'azvnet-*' -type d",
                capture=True,
            ).stdout.strip()
            == ""
        )
        print("PASS all invocation guest directories cleaned", flush=True)


def vnet_acceptance(args: argparse.Namespace) -> None:
    records_path = Path(args.resources)
    records = json.loads(records_path.read_text()) if records_path.exists() else []
    previous_count = len(records)

    def record(group: str, owner: str) -> None:
        records.append({"group": group, "owner": owner, "status": "create-requested"})
        temporary = records_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(records, indent=2) + "\n")
        temporary.replace(records_path)

    with tempfile.TemporaryDirectory(prefix="azvnet-live-config-") as scratch:
        work = Path(scratch)
        (work / "main.tf").write_text(
            'output "proof" { value = "provider-free-live-proof" }\n'
        )
        with VnetTofu(
            tenant_id=os.environ["ARM_TENANT_ID"],
            subscription_id=os.environ["ARM_SUBSCRIPTION_ID"],
            client_id=os.environ["ARM_CLIENT_ID"],
            identity=Identity(args.identity, args.identity_client),
            state_group=args.group,
            state_vnet=args.vnet,
            state_endpoint=args.endpoint,
            workdir=work,
            config_files=["main.tf"],
            tofu_version="1.10.6",
            hosts=[Host(args.group, args.vm)],
            bootstrap=Bootstrap(
                args.location,
                args.subnet,
                "Ubuntu2404",
                args.size,
                priority="Spot",
                max_price=-1,
            ),
            record_bootstrap=record,
        ) as engine:
            vm = engine.session.json(
                "vm", "show", "-d", "-g", args.group, "-n", args.vm
            )
            assert vm["powerState"] == "VM running", (
                "authorized host must already be running"
            )
            subnet_before = engine.session.json(
                "network",
                "vnet",
                "subnet",
                "show",
                "-g",
                args.group,
                "--vnet-name",
                args.vnet,
                "-n",
                args.subnet,
            )
            if args.phase == "host":
                result = engine.run("plan", "-input=false", "-no-color", capture=True)
                assert "provider-free-live-proof" in result.stdout
                assert len(records) == previous_count, (
                    "explicit authorized host unexpectedly fell back to bootstrap"
                )
                print(
                    "PASS permitted host: private DNS/TLS, exact identity binding, actual OpenTofu plan",
                    flush=True,
                )
                # Exercise actual managed identity token acquisition without returning its token.
                proof = engine.remote.sealed(
                    args.group,
                    args.vm,
                    f"""python3 - <<'PY'
import json, urllib.request
url = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F&client_id={args.identity_client}'
request = urllib.request.Request(url, headers={{'Metadata':'true'}})
with urllib.request.urlopen(request, timeout=20) as response:
    document = json.load(response)
assert document['access_token']
print('managed identity token acquired without disclosure')
PY""",
                    capture=True,
                )
                assert "token acquired" in proof.stdout
                print("PASS requested managed identity token acquisition", flush=True)
            elif args.phase == "backend":
                (work / "main.tf").write_text(
                    'terraform {\n backend "azurerm" {\n'
                    f"  resource_group_name = {json.dumps(args.group)}\n"
                    f"  storage_account_name = {json.dumps(args.endpoint.split('.')[0])}\n"
                    f"  container_name = {json.dumps(args.container)}\n"
                    f'  key = "azvnet-live-{secrets.token_hex(12)}.tfstate"\n'
                    "  use_azuread_auth = true\n }\n}\n"
                    'output "proof" { value = "backend-proof" }\n'
                )
                try:
                    engine.run("plan", "-input=false", "-no-color", capture=True)
                except RemoteExecutionError as error:
                    diagnostic = error.stdout + error.stderr
                    assert (
                        "403" in diagnostic
                        or "AuthorizationPermissionMismatch" in diagnostic
                    )
                    assert os.environ["ARM_CLIENT_SECRET"] not in diagnostic
                    Path(args.evidence).write_text(diagnostic)
                    print(
                        "BLOCKED private backend: actual 403; exact nonsecret error saved",
                        flush=True,
                    )
                else:
                    print("PASS private backend plan", flush=True)
            elif args.phase == "bootstrap":
                result = engine.run(
                    "apply", "-auto-approve", "-input=false", "-no-color", capture=True
                )
                assert "Apply complete!" in result.stdout
                print(
                    "PASS cold Spot bootstrap actual OpenTofu apply and cleanup",
                    flush=True,
                )
                try:
                    engine.run("azvnet-invalid-command", capture=True)
                except RemoteExecutionError as error:
                    assert "no command named" in error.stderr
                else:
                    raise AssertionError("guest-failure control succeeded")
                print("PASS actual guest failure bootstrap cleanup", flush=True)
                original = engine.bootstrap
                engine.bootstrap = replace(
                    original, image="azvnet-deliberately-invalid-image"
                )
                try:
                    with redirect_stderr(io.StringIO()):
                        with engine.host(disposable=True):
                            raise AssertionError(
                                "invalid-image creation unexpectedly succeeded"
                            )
                except subprocess.CalledProcessError as error:
                    assert error.returncode != 0
                finally:
                    engine.bootstrap = original
                print(
                    "PASS real invalid-image failure-before-yield cleanup", flush=True
                )
            for entry in records[previous_count:]:
                assert not engine.session.group_exists(entry["group"])
                leftovers = engine.session.json(
                    "resource",
                    "list",
                    "--query",
                    f"[?resourceGroup=='{entry['group']}'].id",
                )
                assert leftovers == []
                entry["status"] = "deleted-verified"
            if len(records) != previous_count:
                records_path.write_text(json.dumps(records, indent=2) + "\n")
            subnet_after = engine.session.json(
                "network",
                "vnet",
                "subnet",
                "show",
                "-g",
                args.group,
                "--vnet-name",
                args.vnet,
                "-n",
                args.subnet,
            )
            assert subnet_before.get("networkSecurityGroup") == subnet_after.get(
                "networkSecurityGroup"
            )
            assert subnet_before.get("natGateway") == subnet_after.get("natGateway")
            print(
                "PASS no recorded bootstrap resources remain; subnet NSG/NAT associations preserved",
                flush=True,
            )


def main() -> None:
    def watchdog_expired(signum, frame):
        raise TimeoutError("outer live-acceptance watchdog expired")

    signal.signal(signal.SIGTERM, watchdog_expired)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "phase", choices=["auth", "remote", "host", "backend", "bootstrap"]
    )
    parser.add_argument("--group")
    parser.add_argument("--vm")
    parser.add_argument("--identity")
    parser.add_argument("--identity-client")
    parser.add_argument("--vnet")
    parser.add_argument("--subnet")
    parser.add_argument("--endpoint")
    parser.add_argument("--location")
    parser.add_argument("--size")
    parser.add_argument("--resources")
    parser.add_argument("--container")
    parser.add_argument("--evidence")
    args = parser.parse_args()
    if args.phase == "auth":
        authentication()
    elif args.phase == "remote":
        if not args.group or not args.vm:
            parser.error("remote requires --group and --vm")
        remote_commands(args.group, args.vm)
    else:
        vnet_acceptance(args)


if __name__ == "__main__":
    main()
