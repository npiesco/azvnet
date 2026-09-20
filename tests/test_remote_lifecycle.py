from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from azvnet import AzvnetError, CleanupResidue
from azvnet.remote import cleanup_after, vm_operation


class LifecycleTests(unittest.TestCase):
    def test_vm_scope_reentrancy_independence_and_exception_release(self):
        entered = threading.Event()
        attempted = threading.Event()
        independent = threading.Event()
        read, write = os.pipe()
        events = []

        def first():
            with vm_operation("SUB", "Group", "VM"):
                with vm_operation("sub", "group", "vm"):
                    events.append("first-enter")
                    entered.set()
                    self.assertEqual(os.read(read, 1), b"x")
                    events.append("first-exit")
                    raise ValueError("synthetic primary")

        def second():
            entered.wait()
            attempted.set()
            with vm_operation("sub", "GROUP", "Vm"):
                events.append("second-enter")

        def other():
            attempted.wait()
            for scope in (
                ("other", "group", "vm"),
                ("sub", "other", "vm"),
                ("sub", "group", "other"),
            ):
                with vm_operation(*scope):
                    subprocess.run([sys.executable, "-c", "pass"], check=True)
            independent.set()

        try:
            with ThreadPoolExecutor(max_workers=3) as pool:
                one, two, three = (
                    pool.submit(first),
                    pool.submit(second),
                    pool.submit(other),
                )
                independent.wait()
                self.assertEqual(events, ["first-enter"])
                os.write(write, b"x")
                with self.assertRaisesRegex(ValueError, "synthetic primary"):
                    one.result()
                two.result()
                three.result()
            self.assertEqual(events, ["first-enter", "first-exit", "second-enter"])
        finally:
            os.close(read)
            os.close(write)

    def test_private_receipts_survive_process_exit_and_concurrent_publication(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch) / "nested" / "residue"
            code = """
from pathlib import Path
import os, sys
from azvnet import CleanupResidue
receipt = CleanupResidue("sub", "group", "vm", "/run/azvnet-" + "a"*48, "Linux", "a"*48)
receipt.write(Path(sys.argv[1]))
os._exit(0)
"""
            children = [
                subprocess.Popen([sys.executable, "-c", code, str(root)])
                for _ in range(4)
            ]
            for child in children:
                self.assertEqual(child.wait(), 0)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            files = list(root.iterdir())
            self.assertEqual(len(files), 4)
            for path in files:
                self.assertEqual(path.stat().st_uid, os.getuid())
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                data = json.loads(path.read_text())
                self.assertEqual(
                    set(data), set(asdict(CleanupResidue("", "", "", "", "", "")))
                )
                self.assertEqual(data["vm"], "vm")
                self.assertIsNone(data["certificate_subject"])

    def test_receipt_rejects_unsafe_directory_and_reports_native_io_error(self):
        receipt = CleanupResidue(
            "sub",
            "g",
            "vm",
            r"C:\ProgramData\azvnet-test",
            "Windows",
            "test",
            "CN=azvnet-test",
        )
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            directory = root / "unsafe"
            directory.mkdir(mode=0o755)
            with self.assertRaises(AzvnetError):
                receipt.write(directory)
            link = root / "alias"
            link.symlink_to(root, target_is_directory=True)
            with self.assertRaises(AzvnetError):
                receipt.write(link)
            blocked = root / "file"
            blocked.touch()
            with self.assertRaises(OSError):
                receipt.write(blocked / "child")
            own = root / "owned"
            own.mkdir(mode=0o700)
            other = 65534 if os.getuid() != 65534 else 0
            subprocess.run(["sudo", "-n", "chown", str(other), str(own)], check=True)
            try:
                with self.assertRaises(AzvnetError):
                    receipt.write(own)
            finally:
                subprocess.run(
                    ["sudo", "-n", "chown", str(os.getuid()), str(own)], check=True
                )

    def test_native_cleanup_failure_keeps_primary_exception(self):
        def failure():
            subprocess.run([sys.executable, "-c", "raise SystemExit(7)"], check=True)

        with self.assertRaisesRegex(ValueError, "primary") as caught:
            with cleanup_after(failure):
                raise ValueError("primary")
        self.assertTrue(
            any("Cleanup also failed" in note for note in caught.exception.__notes__)
        )
        with self.assertRaises(subprocess.CalledProcessError):
            with cleanup_after(failure):
                pass
