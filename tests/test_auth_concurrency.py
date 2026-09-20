from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

from azvnet import AzureSession


class AuthenticationConcurrencyTests(unittest.TestCase):
    def test_actual_unauthenticated_cli_failure_releases_session_lock(self):
        with tempfile.TemporaryDirectory() as scratch:
            env = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("ARM_") and key != "AZVNET_CREDENTIAL_FILE"
            }
            env["AZURE_CONFIG_DIR"] = scratch
            barrier = threading.Barrier(2)
            with AzureSession(
                tenant_id="00000000-0000-0000-0000-000000000001",
                subscription_id="00000000-0000-0000-0000-000000000002",
                interactive=True,
                environ=env,
            ) as session:

                def login():
                    barrier.wait()
                    with self.assertRaises(subprocess.CalledProcessError) as caught:
                        session.login()
                    self.assertIn("az login", caught.exception.stderr)
                    self.assertFalse(session._authenticated)

                with (
                    redirect_stderr(io.StringIO()),
                    ThreadPoolExecutor(max_workers=2) as pool,
                ):
                    jobs = [pool.submit(login) for _ in range(2)]
                    for job in jobs:
                        job.result()
                self.assertTrue(Path(scratch).is_dir())
                self.assertEqual(session.env["AZURE_CONFIG_DIR"], scratch)
            self.assertTrue(Path(scratch).is_dir())
