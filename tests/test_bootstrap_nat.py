from pathlib import Path
import tempfile
import unittest

from azvnet import Bootstrap, Identity, VnetTofu


class BootstrapNATTests(unittest.TestCase):
    def test_explicit_nat_only_adds_private_creation_arguments(self):
        nat = "/subscriptions/sub/resourceGroups/network/providers/Microsoft.Network/natGateways/egress"
        legacy = Bootstrap(
            "region", "subnet", "image", "size", subnet_cidr="10.0.0.0/24"
        )
        self.assertEqual(legacy.subnet_arguments(), [])
        explicit = Bootstrap(
            "region",
            "subnet",
            "image",
            "size",
            subnet_cidr="10.0.0.0/24",
            nat_gateway_id=nat,
        )
        self.assertEqual(
            explicit.subnet_arguments(),
            ["--nat-gateway", nat, "--default-outbound-access", "false"],
        )
        for invalid in (
            "egress",
            nat + "/child",
            nat + "?api-version=invalid",
            nat + " space",
            nat.replace("natGateways", "publicIPAddresses"),
        ):
            with self.assertRaises(ValueError):
                Bootstrap(
                    "region",
                    "subnet",
                    "image",
                    "size",
                    subnet_cidr="10.0.0.0/24",
                    nat_gateway_id=invalid,
                )
        with self.assertRaises(ValueError):
            Bootstrap("region", "subnet", "image", "size", nat_gateway_id=nat)
        with (
            tempfile.TemporaryDirectory() as scratch,
            self.assertRaisesRegex(ValueError, "configured subscription"),
        ):
            VnetTofu(
                tenant_id="tenant",
                subscription_id="other",
                client_id="client",
                identity=Identity("/subscriptions/other/identity", "identity"),
                state_group="group",
                state_vnet="vnet",
                state_endpoint="example.invalid",
                workdir=Path(scratch),
                bootstrap=explicit,
                tofu_version="1.10.6",
                environ={"ARM_CLIENT_SECRET": "synthetic"},
            )
