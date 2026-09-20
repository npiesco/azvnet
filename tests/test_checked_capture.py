from contextlib import redirect_stderr, redirect_stdout
import io
import subprocess
import sys
import unittest

from azvnet import checked


class CheckedCaptureTests(unittest.TestCase):
    def test_failed_captured_process_retains_stdout_only_in_exception(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                checked(
                    [
                        sys.executable,
                        "-c",
                        "import sys; print('synthetic-partial-export'); print('synthetic-diagnostic',file=sys.stderr); sys.exit(17)",
                    ],
                    capture=True,
                )
        self.assertEqual(caught.exception.returncode, 17)
        self.assertEqual(caught.exception.stdout, "synthetic-partial-export\n")
        self.assertEqual(caught.exception.stderr, "synthetic-diagnostic\n")
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("synthetic-partial-export", errors.getvalue())
        self.assertIn("synthetic-diagnostic", errors.getvalue())

    def test_success_capture_remains_private(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            result = checked(
                [sys.executable, "-c", "print('synthetic-success')"],
                capture=True,
            )
        self.assertEqual(result.stdout, "synthetic-success\n")
        self.assertEqual((output.getvalue(), errors.getvalue()), ("", ""))
