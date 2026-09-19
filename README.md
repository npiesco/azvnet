# azvnet

Your OpenTofu state can sit behind an Azure private endpoint while your terminal
has no route into its VNet. Destroying the last VM should not leave you unable
to create the next one.

**azvnet runs OpenTofu inside the VNet, through Azure Run Command.**

From a checkout, install the package and its validation tools:

```sh
uv sync --locked
```

With infrastructure in `infra/` and the configuration below saved as
`azvnet.json`:

```python
import json
from pathlib import Path

from azvnet import Bootstrap, Host, Identity, VnetTofu

config = json.loads(Path("azvnet.json").read_text())
identity = Identity(**config.pop("identity"))
bootstrap = Bootstrap(**config.pop("bootstrap"))
hosts = [Host(**host) for host in config.pop("hosts")]

with VnetTofu(
    **config,
    identity=identity,
    bootstrap=bootstrap,
    hosts=hosts,
    workdir=Path("infra"),
) as tofu:
    tofu.run("plan", "-input=false", variables={"enabled": True})
```

The configuration is explicit. Replace every placeholder with your own
deployment values; `enabled` must be an input declared by that configuration.

```json
{
  "tenant_id": "<tenant UUID>",
  "subscription_id": "<subscription UUID>",
  "client_id": "<service-principal application UUID>",
  "identity": {
    "resource_id": "/subscriptions/<subscription UUID>/resourceGroups/<identity group>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<identity name>",
    "client_id": "<managed-identity application UUID>"
  },
  "state_group": "<group containing the state VNet>",
  "state_vnet": "<state VNet name>",
  "state_endpoint": "<storage account>.blob.core.windows.net",
  "bootstrap": {
    "location": "<state VNet region>",
    "subnet": "<subnet in the state VNet>",
    "image": "Ubuntu2404",
    "size": "<permitted Linux VM size>"
  },
  "tofu_version": "1.10.6",
  "hosts": []
}
```

You still need Python 3.12+, Azure CLI, OpenSSL and `ssh-keygen` locally.
Guests need Bash, Python 3, OpenSSL, curl and tar. State storage, private DNS,
the VNet, outbound access and a user-assigned managed identity with
provider/backend permissions must already exist. The service principal needs
Run Command, VM/identity-attachment and task-resource-group create/delete
permissions. azvnet does not grant roles or build your persistent VNet.
The subnet must exist unless `Bootstrap(subnet_cidr="...")` explicitly permits
on-demand creation. Subnets are enumerated with a checked request first;
authentication failures cannot be mistaken for absence. Existing subnets and
their NSG/NAT associations are left unchanged.

## Authenticate without changing your CLI context

Supply `ARM_CLIENT_SECRET` through your process environment. Tenant,
subscription and client come from constructor arguments; conflicting `ARM_*`
values are rejected. Alternatively, pass `credential_file=Path(...)` pointing
to a current-user-owned, non-symlink, mode-0600 file:

```text
Tenant: <tenant UUID>
Client ID: <application UUID>
Secret: <runtime secret>
```

No credential filename is assumed. Do not commit this file.

Set `AZVNET_CLI_PYTHON` to the interpreter containing your installed
`azure.cli` module (for the Microsoft Debian package, typically
`/opt/az/bin/python3`). You can instead pass `cli_python=Path(...)`.
Login invokes that CLI over stdin so its secret never enters the OS command
line. Each service-principal session owns a mode-0700 temporary Azure config
directory and removes it on exit. It never changes global `os.environ` or
calls `az account set`.
On Linux, `TMPDIR=/dev/shm` keeps temporary credentials and transport keys in
memory-backed storage (the caller must still close the session).

## Keep local state local

`AzureSession` works independently of private-VNet configuration:

```python
import os
from pathlib import Path

from azvnet import AzureSession

with AzureSession(
    tenant_id=os.environ["ARM_TENANT_ID"],
    subscription_id=os.environ["ARM_SUBSCRIPTION_ID"],
    client_id=os.environ.get("ARM_CLIENT_ID"),
    interactive=True,
) as azure:
    azure.local_tofu(
        "init", "-reconfigure",
        "-backend-config=path=.local/personal/terraform.tfstate",
        workdir=Path("infra"),
    )
    azure.local_tofu("plan", "-input=false", workdir=Path("infra"))
```

This example assumes a `backend "local"` configuration. With no SP secret or
credential file, `interactive=True` validates a cached user account for the
specified tenant/subscription. It does not switch the default account.
Service-principal authentication takes precedence when supplied.

## Select a host without adopting somebody else's VM

`hosts=[Host(group="...", name="...")]` is an explicit allowlist, not a fleet
search. A host must be a provisioned Linux VM, resolve the state endpoint
privately and complete a TLS connection to it. A stopped configured host is
started through a synchronous CLI operation. Identity attachment is checked.
Backend authentication and permissions are then checked by `tofu init`.

When no configured host reaches state, azvnet creates a uniquely named,
ownership-tagged resource group containing a throwaway VM, NIC and disk, with
no public IP. Its NIC uses your existing state subnet. Cleanup covers VM
creation, identity attachment, reachability, execution and failure before the
host is yielded. Deletion requires the exact invocation's ownership tag and
checks that the group is gone. Nothing is deleted by name prefix.

Regular pricing is the default. Spot requires explicit
`Bootstrap(..., priority="Spot", max_price=-1)` (or a nonnegative maximum
price). Spot uses Azure's `Delete` eviction policy. The configured SKU, region
and pricing model are never replaced with a fallback. Pass
`record_bootstrap=callback` to persist `(group_name, ownership_token)` before
each group-create request, for recovery if the caller is terminated.

Mutating OpenTofu commands always use a throwaway host outside the managed
fleet, so apply/destroy cannot delete their execution host. Cleanup failures
are errors; if an operation already failed, cleanup is reported without
replacing the primary exception. An unavailable Azure control plane can still
prevent deletion: inspect the reported group, verify its ownership tag, and
remove that exact group once access is restored.

## What crosses Run Command

`Remote(azure).run(group, name, script)` is for non-sensitive scripts.
`Remote(azure).sealed(...)` encrypts the payload to a fresh guest certificate
before submitting it and encrypts stdout/stderr back to an invocation-scoped
caller key. Linux decrypts in a private `/run` directory; Windows
uses a restricted directory and a task-specific machine certificate. Guest
keys and plaintext are removed after execution. Azure's retained agent scripts
contain setup, ciphertext and cleanup commands, not decrypted input or output.
Scripts must not pass secrets to programs in argv. Use `capture=True` when
output contains secrets; it suppresses local printing as well.

Sealed output is bounded to 8 MiB before JSON encoding and returned through
fixed-size encrypted chunks with exact lengths. Retrieval iterates over the
manifest's known length, never readiness polling. Truncated/missing chunks fail
closed. Guest plaintext is removed before retrieval, and ciphertext is removed
by caller cleanup. Azure permits only one action Run Command at a time per VM:
concurrent requests can produce an explicit Azure conflict, never a substituted
result. Each invocation has independent keys and directories.

`VnetTofu` uses sealed transport for configuration, variables and state
migration. Guest OpenTofu authenticates with managed identity, never the
service-principal secret. Each invocation has a private work directory; the
default bundle includes only top-level `*.tf` and `.terraform.lock.hcl`.
Pass `config_files=[...]` for additional templates or local module files.
Symlink and out-of-tree members are rejected. JSON variable values retain their
types, and explicit `-var-file` inputs are copied and renamed inside the guest.
Inline `-var` arguments are rejected; use `variables={...}`.

`migrate_state(Path(...))` transfers local state over the same sealed channel
and performs a non-forced `tofu state push`. Serial/lineage conflicts remain
errors. Remote plan files are ephemeral, so `-out` and workstation state paths
are rejected rather than advertised as downloadable artifacts.

Every call requires CLI success, ARM success and an exact, fresh completion
line in stdout. A marker in stderr, a substring, a stale marker or a truncated
response is a failure. Output frames also detect truncation that retains the
completion line. Non-sensitive Run Command failures print diagnostic output.
Sealed guest failures raise `RemoteExecutionError`; inspect its `returncode`,
`stdout` and `stderr` privately. Its message does not print decrypted output.
Successful capture returns stdout without Azure wrappers or the proof line.
State pulls and raw/JSON show/output require `capture=True` so they are not
printed to logs; the returned data still needs to be handled as sensitive.
Unsealed output remains limited by Azure's response size. Sealed output uses
bounded chunk retrieval; even small responses require additional CLI calls.

## Install a wheel without another credential

The package has no runtime Python dependencies and no dependency on a consumer
repository. Build a wheel from the checkout:

```sh
uv build --out-dir dist &&
uv pip install --python /path/to/venv/bin/python dist/azvnet-0.1.0-py3-none-any.whl
```

Consumers can pin a reviewed public Git commit or distribute this wheel with
its SHA-256 digest. No GitHub PAT or deploy key is needed for public source.
Consumers can validate this wheel before their pinned commit is public.
Publishing source and validating a public install are separate release steps.

## Testing

```sh
uv sync --locked &&
uv run ruff check src tests &&
uv run mypy src &&
AZVNET_CLI_PYTHON=/opt/az/bin/python3 uv run python -m unittest discover -s tests -v
```

Tests execute installed Azure CLI without authentication, OpenTofu against
provider-free configurations, Bash and OpenSSL. They do not replace executables
or cloud calls with fake implementations. Parser tests use concrete ARM
responses, including failed and truncated messages.

Live acceptance additionally requires isolated SP login, private endpoint
access, explicit-host identity attachment, bootstrap creation/deletion,
failure-before-yield cleanup and Windows Run Command. Those operations need an
authorized test subscription and are not part of the offline test command.
