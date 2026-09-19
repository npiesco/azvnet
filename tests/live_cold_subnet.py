"""Authorized missing-subnet bootstrap proof; all cloud targets are explicit."""

import argparse
import json
import os
from pathlib import Path
import signal
import tempfile

from azvnet import Bootstrap, Identity, VnetTofu


def main():
    parser = argparse.ArgumentParser()
    for name in (
        "group",
        "vnet",
        "subnet",
        "cidr",
        "nat",
        "identity",
        "identity-client",
        "endpoint",
        "location",
        "size",
        "resources",
        "evidence",
    ):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()

    def timeout(signum, frame):
        raise TimeoutError("outer bootstrap proof watchdog")

    signal.signal(signal.SIGTERM, timeout)
    journal = Path(args.resources)
    records = json.loads(journal.read_text()) if journal.exists() else []
    start = len(records)

    def save():
        with tempfile.NamedTemporaryFile(
            mode="w", dir=journal.parent, delete=False
        ) as stream:
            staged = Path(stream.name)
            try:
                json.dump(records, stream, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
                os.replace(staged, journal)
                fd = os.open(journal.parent, os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                staged.unlink(missing_ok=True)

    def record(group, owner):
        records.append(
            {
                "group": group,
                "owner": owner,
                "status": "create-requested",
                "proof": "missing-subnet-nat",
            }
        )
        save()

    def associations(subnet):
        return {
            key: subnet.get(key)
            for key in (
                "id",
                "addressPrefix",
                "addressPrefixes",
                "natGateway",
                "networkSecurityGroup",
                "routeTable",
                "defaultOutboundAccess",
            )
        }

    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        (work / "main.tf").write_text(
            'output "proof" { value = "cold-private-subnet-proof" }\n'
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
            bootstrap=Bootstrap(
                args.location,
                args.subnet,
                "Ubuntu2404",
                args.size,
                subnet_cidr=args.cidr,
                nat_gateway_id=args.nat,
                priority="Spot",
                max_price=-1,
            ),
            record_bootstrap=record,
        ) as engine:
            before = engine.session.json(
                "network",
                "vnet",
                "subnet",
                "list",
                "-g",
                args.group,
                "--vnet-name",
                args.vnet,
            )
            assert all(item["name"] != args.subnet for item in before), (
                "authorized cold subnet already exists"
            )
            result = engine.run(
                "apply", "-auto-approve", "-input=false", "-no-color", capture=True
            )
            assert (
                "Apply complete!" in result.stdout
                and "cold-private-subnet-proof" in result.stdout
            )
            print(
                "PASS missing-subnet Spot bootstrap: private DNS/TLS and actual provider-free OpenTofu",
                flush=True,
            )
            after = engine.session.json(
                "network",
                "vnet",
                "subnet",
                "list",
                "-g",
                args.group,
                "--vnet-name",
                args.vnet,
            )
            created = next(item for item in after if item["name"] == args.subnet)
            assert created["natGateway"]["id"].lower() == args.nat.lower()
            assert created["defaultOutboundAccess"] is False
            assert created.get("addressPrefix") == args.cidr or created.get(
                "addressPrefixes"
            ) == [args.cidr]
            for original in before:
                current = next(item for item in after if item["id"] == original["id"])
                assert associations(original) == associations(current)
            for entry in records[start:]:
                assert not engine.session.group_exists(entry["group"])
                leftovers = engine.session.json(
                    "resource",
                    "list",
                    "--query",
                    f"[?resourceGroup=='{entry['group']}'].id",
                )
                assert leftovers == []
                entry["status"] = "deleted-verified"
            assert len(records) == start + 1
            save()
            evidence = {
                "created_subnet": associations(created),
                "existing_subnets_preserved": [associations(item) for item in before],
                "bootstrap_groups": records[start:],
            }
            Path(args.evidence).write_text(json.dumps(evidence, indent=2) + "\n")
            cache = Path(engine.session.env["AZURE_CONFIG_DIR"])
            print(
                "PASS exact bootstrap group/VM/NIC/disk absence; existing subnet NAT/routes/NSGs unchanged",
                flush=True,
            )
            print(
                "PASS created subnet NAT/private-outbound verified; managed NSG retained:",
                bool(created.get("networkSecurityGroup")),
                flush=True,
            )
        assert not cache.exists()
        print(
            "PASS private CLI cache removed; task subnet retained for parent VNet teardown",
            flush=True,
        )


if __name__ == "__main__":
    main()
