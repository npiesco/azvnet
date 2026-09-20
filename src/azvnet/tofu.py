from __future__ import annotations

import base64
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import io
import ipaddress
import json
import math
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import tarfile
import tempfile

from .auth import AzureSession, AzvnetError, checked, require_capture
from .remote import Remote, cleanup_after
from .residue import CleanupResidue


@dataclass(frozen=True)
class Identity:
    resource_id: str
    client_id: str


@dataclass(frozen=True)
class Host:
    group: str
    name: str


@dataclass(frozen=True)
class Bootstrap:
    location: str
    subnet: str
    image: str
    size: str
    subnet_cidr: str | None = None
    priority: str = "Regular"
    max_price: float | None = None
    nat_gateway_id: str | None = None

    def __post_init__(self) -> None:
        if self.subnet_cidr is not None:
            ipaddress.ip_network(self.subnet_cidr)
        if self.nat_gateway_id is not None:
            if self.subnet_cidr is None:
                raise ValueError("nat_gateway_id requires explicit subnet_cidr")
            if not re.fullmatch(
                r"/subscriptions/[^/\s?#]+/resourceGroups/[^/\s?#]+/providers/Microsoft\.Network/natGateways/[^/\s?#]+",
                self.nat_gateway_id,
                re.IGNORECASE,
            ):
                raise ValueError(
                    "nat_gateway_id must be a full NAT gateway resource ID"
                )
        if self.priority not in {"Regular", "Spot"}:
            raise ValueError("bootstrap priority must be Regular or Spot")
        if self.priority == "Spot" and (
            self.max_price is None
            or not math.isfinite(self.max_price)
            or (self.max_price < 0 and self.max_price != -1)
        ):
            raise ValueError(
                "Spot requires explicit max_price (-1 or a nonnegative price)"
            )
        if self.priority == "Regular" and self.max_price is not None:
            raise ValueError("max_price is only valid for Spot")

    def capacity_arguments(self) -> list[str]:
        if self.priority == "Spot":
            return [
                "--priority",
                "Spot",
                "--eviction-policy",
                "Delete",
                "--max-price",
                str(self.max_price),
            ]
        return ["--priority", "Regular"]

    def subnet_arguments(self) -> list[str]:
        if self.nat_gateway_id is None:
            return []
        return [
            "--nat-gateway",
            self.nat_gateway_id,
            "--default-outbound-access",
            "false",
        ]


def tf_var_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """Keep raw variable text for OpenTofu's declared-type interpretation."""
    return {key: value for key, value in environ.items() if key.startswith("TF_VAR_")}


def configuration_bundle(workdir: Path, files: Sequence[str]) -> str:
    root = workdir.resolve()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name in sorted(set(files)):
            path = workdir / name
            if (
                Path(name).is_absolute()
                or ".." in Path(name).parts
                or path.is_symlink()
                or not path.is_file()
                or not path.resolve().is_relative_to(root)
            ):
                raise AzvnetError(
                    f"configuration member must be a regular file inside workdir: {name}"
                )
            content = path.read_bytes()
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(content), 0o600
            archive.addfile(info, io.BytesIO(content))
    return base64.b64encode(output.getvalue()).decode("ascii")


def remote_arguments(
    arguments: Sequence[str],
    workdir: Path,
) -> tuple[list[str], dict[str, bytes]]:
    """Relocate explicit var-files; never pass a workstation path to the guest."""
    result: list[str] = []
    files: dict[str, bytes] = {}
    position = 0
    while position < len(arguments):
        argument = arguments[position]
        if argument == "-var" or argument.startswith("-var="):
            raise AzvnetError(
                "pass variables as a mapping, not process-visible -var arguments"
            )
        if argument == "-var-file" or argument.startswith("-var-file="):
            if argument == "-var-file":
                position += 1
                if position == len(arguments):
                    raise AzvnetError("-var-file requires a path")
                value = arguments[position]
            else:
                value = argument.split("=", 1)[1]
            source = Path(value)
            if not source.is_absolute():
                source = workdir / source
            suffix = ".tfvars.json" if source.name.endswith(".json") else ".tfvars"
            name = f"input-{len(files)}{suffix}"
            files[name] = source.read_bytes()
            result.append(f"-var-file={name}")
        elif argument.startswith(
            ("-out", "-state", "-backup", "-chdir", "-backend-config")
        ):
            raise AzvnetError(
                f"remote file/control argument requires a dedicated API: {argument.split('=')[0]}"
            )
        elif argument.startswith("/") or (
            not argument.startswith("-") and "/" in argument
        ):
            raise AzvnetError("remote arguments cannot refer to workstation paths")
        else:
            result.append(argument)
        position += 1
    return result, files


def guest_script(
    *,
    bundle: str,
    arguments: Sequence[str],
    variables: Mapping[str, object],
    files: Mapping[str, bytes],
    tenant_id: str,
    subscription_id: str,
    identity: Identity,
    tofu_version: str,
    tf_var_env: Mapping[str, str] | None = None,
) -> str:
    if not arguments:
        raise ValueError("an OpenTofu command is required")
    if not re.fullmatch(r"\d+\.\d+\.\d+", tofu_version):
        raise ValueError("tofu_version must be an exact x.y.z version")
    values = base64.b64encode(json.dumps(dict(variables)).encode()).decode()
    script = f"""set -euo pipefail
umask 077
work=$(mktemp -d "${{TMPDIR:-/tmp}}/azvnet-tofu-XXXXXXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
cd "$work"
printf %s {shlex.quote(bundle)} | base64 -d | tar xzf -
printf %s {values} | base64 -d > azvnet.auto.tfvars.json
if ! command -v tofu >/dev/null || ! tofu version -json | python3 -c 'import json,sys; sys.exit(json.load(sys.stdin)["terraform_version"] != "{tofu_version}")'; then
  case "$(uname -m)" in aarch64|arm64) arch=arm64 ;; x86_64) arch=amd64 ;; *) echo "Unsupported host architecture" >&2; exit 1 ;; esac
  archive="tofu_{tofu_version}_linux_${{arch}}.tar.gz"
  base=https://github.com/opentofu/opentofu/releases/download/v{tofu_version}
  curl -fsSLo "$archive" "$base/$archive"
  curl -fsSLo checksums "$base/tofu_{tofu_version}_SHA256SUMS"
  grep -F "  $archive" checksums > selected-checksum
  sha256sum -c selected-checksum
  mkdir bin
  tar xzf "$archive" -C bin tofu
  export PATH="$work/bin:$PATH"
fi
unset ARM_CLIENT_SECRET ARM_CLIENT_CERTIFICATE_PATH ARM_OIDC_TOKEN ARM_OIDC_TOKEN_FILE_PATH
export ARM_USE_MSI=true ARM_USE_CLI=false
export ARM_CLIENT_ID={shlex.quote(identity.client_id)}
export ARM_TENANT_ID={shlex.quote(tenant_id)}
export ARM_SUBSCRIPTION_ID={shlex.quote(subscription_id)}
export TF_IN_AUTOMATION=1 TF_DATA_DIR="$work/.terraform"
"""
    for key, value in (tf_var_env or {}).items():
        if not re.fullmatch(r"TF_VAR_[a-zA-Z_][a-zA-Z0-9_]*", key):
            raise ValueError("tf_var_env keys must be TF_VAR_ shell identifiers")
        if not isinstance(value, str) or "\0" in value:
            raise ValueError("tf_var_env values must be strings without NUL bytes")
        script += f"export {key}={shlex.quote(value)}\n"
    for name, content in files.items():
        if Path(name).name != name or name in {".", ".."}:
            raise ValueError("payload filenames must be basenames")
        script += f"printf %s {base64.b64encode(content).decode()} | base64 -d > {shlex.quote(name)}\n"
    if arguments[0] != "init":
        script += "tofu init -input=false -no-color >/dev/null\n"
    script += f"tofu {shlex.join(arguments)}\n"
    return script


def endpoint_probe_script(endpoint: str) -> str:
    return f"""python3 - <<'PY'
import ipaddress, socket, ssl
try:
    addresses = socket.getaddrinfo({endpoint!r}, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(entry[4][0]).is_private for entry in addresses):
        raise OSError("state endpoint does not resolve privately")
    with socket.create_connection(({endpoint!r}, 443)) as connection:
        with ssl.create_default_context().wrap_socket(connection, server_hostname={endpoint!r}):
            pass
except OSError:
    print("unreachable")
else:
    print("reachable")
PY"""


class VnetTofu:
    """OpenTofu over Run Command with an explicit host or an owned bootstrap."""

    def __init__(
        self,
        *,
        tenant_id: str,
        subscription_id: str,
        client_id: str,
        identity: Identity,
        state_group: str,
        state_vnet: str,
        workdir: Path,
        state_endpoint: str,
        bootstrap: Bootstrap,
        tofu_version: str,
        hosts: Sequence[Host] = (),
        credential_file: Path | None = None,
        cli_python: Path | None = None,
        config_files: Sequence[str] | None = None,
        environ: Mapping[str, str] | None = None,
        record_bootstrap: Callable[[str, str], None] | None = None,
        record_cleanup: Callable[[CleanupResidue], object] | None = None,
    ):
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", state_endpoint):
            raise ValueError("state_endpoint must be a DNS hostname")
        prefix = f"/subscriptions/{subscription_id}/"
        if not identity.resource_id.lower().startswith(prefix.lower()):
            raise ValueError(
                "managed identity must belong to the configured subscription"
            )
        if (
            bootstrap.nat_gateway_id is not None
            and not bootstrap.nat_gateway_id.lower().startswith(prefix.lower())
        ):
            raise ValueError("NAT gateway must belong to the configured subscription")
        self.session = AzureSession(
            tenant_id=tenant_id,
            subscription_id=subscription_id,
            client_id=client_id,
            credential_file=credential_file,
            cli_python=cli_python,
            environ=environ,
        )
        self.remote = Remote(self.session, record_cleanup=record_cleanup)
        self.identity, self.workdir = identity, workdir
        self.state_group, self.state_vnet = state_group, state_vnet
        self.state_endpoint, self.bootstrap = state_endpoint, bootstrap
        self.record_bootstrap = record_bootstrap
        self.hosts, self.tofu_version = tuple(hosts), tofu_version
        self.config_files = (
            tuple(config_files)
            if config_files is not None
            else (
                *(p.name for p in workdir.glob("*.tf")),
                ".terraform.lock.hcl",
            )
        )

    def __enter__(self) -> VnetTofu:
        return self

    def __exit__(self, *exc: object) -> None:
        self.session.close()

    def _reachable(self, host: Host) -> bool:
        result = self.remote.run(
            host.group,
            host.name,
            endpoint_probe_script(self.state_endpoint),
            capture=True,
        ).stdout.strip()
        if result not in {"reachable", "unreachable"}:
            raise AzvnetError(
                "state endpoint reachability check returned invalid proof"
            )
        return result == "reachable"

    def _attach(self, host: Host) -> None:
        self.session.run(
            "vm",
            "identity",
            "assign",
            "-g",
            host.group,
            "-n",
            host.name,
            "--identities",
            self.identity.resource_id,
            "--output",
            "none",
        )
        identities = self.session.json(
            "vm",
            "identity",
            "show",
            "-g",
            host.group,
            "-n",
            host.name,
        ).get("userAssignedIdentities", {})
        assigned = {key.lower(): value for key, value in identities.items()}
        if self.identity.resource_id.lower() not in assigned:
            raise AzvnetError("managed identity attachment was not confirmed")
        if (
            assigned[self.identity.resource_id.lower()]["clientId"].lower()
            != self.identity.client_id.lower()
        ):
            raise AzvnetError(
                "attached managed identity conflicts with configured client_id"
            )

    @contextmanager
    def host(self, *, disposable: bool = False) -> Iterator[Host]:
        if not disposable:
            for host in self.hosts:
                if not self.session.group_exists(host.group):
                    continue
                machines = self.session.json("vm", "list", "-d", "-g", host.group)
                machine = next(
                    (item for item in machines if item["name"] == host.name), None
                )
                if machine is None:
                    continue
                if (
                    machine["storageProfile"]["osDisk"]["osType"] != "Linux"
                    or machine.get("provisioningState") != "Succeeded"
                ):
                    raise AzvnetError(
                        f"configured host {host.name} is not a provisioned Linux VM"
                    )
                if machine.get("powerState") != "VM running":
                    self.session.run(
                        "vm", "start", "-g", host.group, "-n", host.name, "-o", "none"
                    )
                if self._reachable(host):
                    self._attach(host)
                    yield host
                    return
        with self._bootstrap() as host:
            yield host

    @contextmanager
    def _bootstrap(self) -> Iterator[Host]:
        owner = secrets.token_hex(24)
        group, name = f"azvnet-{owner}", f"bootstrap-{owner[:24]}"
        if self.session.group_exists(group):
            raise AzvnetError("refusing to adopt a pre-existing bootstrap group")
        subnets = self.session.json(
            "network",
            "vnet",
            "subnet",
            "list",
            "-g",
            self.state_group,
            "--vnet-name",
            self.state_vnet,
        )
        existing = next(
            (item for item in subnets if item["name"] == self.bootstrap.subnet), None
        )
        if existing is None:
            if self.bootstrap.subnet_cidr is None:
                raise AzvnetError(
                    "bootstrap subnet is absent and no subnet_cidr was configured"
                )
            if self.bootstrap.nat_gateway_id is not None:
                gateway = self.session.json(
                    "network",
                    "nat",
                    "gateway",
                    "show",
                    "--ids",
                    self.bootstrap.nat_gateway_id,
                )
                vnet = self.session.json(
                    "network",
                    "vnet",
                    "show",
                    "-g",
                    self.state_group,
                    "-n",
                    self.state_vnet,
                )
                if (
                    gateway.get("id", "").lower()
                    != self.bootstrap.nat_gateway_id.lower()
                    or gateway.get("provisioningState") != "Succeeded"
                    or gateway.get("location", "").lower()
                    != vnet.get("location", "").lower()
                    or gateway.get("location", "").lower()
                    != self.bootstrap.location.lower()
                ):
                    raise AzvnetError(
                        "configured NAT gateway identity, region or provisioning proof failed"
                    )
            existing = self.session.json(
                "network",
                "vnet",
                "subnet",
                "create",
                "-g",
                self.state_group,
                "--vnet-name",
                self.state_vnet,
                "-n",
                self.bootstrap.subnet,
                "--address-prefixes",
                self.bootstrap.subnet_cidr,
                *self.bootstrap.subnet_arguments(),
            )
            existing = existing.get("newSubnet", existing)
            if self.bootstrap.nat_gateway_id is not None and (
                existing.get("natGateway", {}).get("id", "").lower()
                != self.bootstrap.nat_gateway_id.lower()
                or existing.get("defaultOutboundAccess") is not False
            ):
                raise AzvnetError(
                    "created subnet did not retain explicit NAT/private-outbound configuration"
                )
        subnet = existing["id"]

        def cleanup() -> None:
            if not self.session.group_exists(group):
                return
            actual = self.session.json("group", "show", "-n", group)
            if actual.get("tags", {}).get("azvnet-owner") != owner:
                raise AzvnetError(
                    f"refusing cleanup of unowned bootstrap group {group}"
                )
            self.session.run("group", "delete", "-n", group, "--yes", "-o", "none")
            if self.session.group_exists(group):
                raise AzvnetError(f"bootstrap group still exists: {group}")

        with cleanup_after(cleanup):
            print(f"azvnet task-owned bootstrap group: {group}", file=sys.stderr)
            if self.record_bootstrap is not None:
                self.record_bootstrap(group, owner)
            self.session.run(
                "group",
                "create",
                "-n",
                group,
                "-l",
                self.bootstrap.location,
                "--tags",
                f"azvnet-owner={owner}",
                "-o",
                "none",
            )
            with tempfile.TemporaryDirectory(prefix="azvnet-key-") as scratch:
                key = Path(scratch) / "key"
                checked(["ssh-keygen", "-t", "ed25519", "-f", str(key), "-N", "", "-q"])
                public = key.with_suffix(".pub").read_text().strip()
            self.session.run(
                "vm",
                "create",
                "-g",
                group,
                "-n",
                name,
                "-l",
                self.bootstrap.location,
                "--image",
                self.bootstrap.image,
                "--size",
                self.bootstrap.size,
                *self.bootstrap.capacity_arguments(),
                "--subnet",
                subnet,
                "--public-ip-address",
                "",
                "--nsg",
                "",
                "--admin-username",
                "azureuser",
                "--ssh-key-values",
                public,
                "--assign-identity",
                self.identity.resource_id,
                "--os-disk-delete-option",
                "Delete",
                "--nic-delete-option",
                "Delete",
                "--tags",
                f"azvnet-owner={owner}",
                "-o",
                "none",
            )
            host = Host(group, name)
            vm = self.session.json("vm", "show", "-g", group, "-n", name)
            if (
                vm["storageProfile"]["osDisk"]["osType"] != "Linux"
                or vm.get("provisioningState") != "Succeeded"
                or vm.get("tags", {}).get("azvnet-owner") != owner
                or vm.get("priority", "Regular") != self.bootstrap.priority
            ):
                raise AzvnetError("bootstrap ownership or suitability proof failed")
            if (
                self.bootstrap.priority == "Spot"
                and vm.get("billingProfile", {}).get("maxPrice")
                != self.bootstrap.max_price
            ):
                raise AzvnetError(
                    "bootstrap Spot price differs from explicit configuration"
                )
            self._attach(host)
            if not self._reachable(host):
                raise AzvnetError(
                    "bootstrap cannot reach the configured state endpoint"
                )
            yield host

    def run(
        self,
        *arguments: str,
        variables: Mapping[str, object] | None = None,
        tf_var_env: Mapping[str, str] | None = None,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        if not arguments:
            raise ValueError("an OpenTofu command is required")
        require_capture(arguments, capture)
        args, files = remote_arguments(arguments, self.workdir)
        script = guest_script(
            bundle=configuration_bundle(self.workdir, self.config_files),
            arguments=args,
            variables=variables or {},
            tf_var_env=tf_var_env,
            files=files,
            tenant_id=self.session.tenant_id,
            subscription_id=self.session.subscription_id,
            identity=self.identity,
            tofu_version=self.tofu_version,
        )
        # Apply can replace its own host too. Only read-only work reuses a host.
        disposable = args[0] not in {"init", "plan", "validate", "output", "show"}
        with self.host(disposable=disposable) as host:
            return self.remote.sealed(host.group, host.name, script, capture=capture)

    def migrate_state(self, path: Path) -> subprocess.CompletedProcess[str]:
        script = guest_script(
            bundle=configuration_bundle(self.workdir, self.config_files),
            arguments=["state", "push", "migrated.tfstate"],
            variables={},
            files={"migrated.tfstate": path.read_bytes()},
            tenant_id=self.session.tenant_id,
            subscription_id=self.session.subscription_id,
            identity=self.identity,
            tofu_version=self.tofu_version,
        )
        with self.host(disposable=True) as host:
            return self.remote.sealed(host.group, host.name, script)
