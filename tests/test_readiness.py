from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from azvnet import non_azure_env
from azvnet.tofu import endpoint_probe_script


TLS_SERVER = r"""
import socket, ssl, sys
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.2", 443))
    listener.listen()
    print("listening", flush=True)
    connection, _ = listener.accept()
    with connection:
        print("accepted", flush=True)
        if sys.stdin.readline().strip() != "handshake":
            raise SystemExit("handshake release channel closed")
        try:
            with context.wrap_socket(connection, server_side=True):
                print("TLS established", flush=True)
        except ssl.SSLError:
            print("TLS rejected", flush=True)
"""


class EndpointCompletionTests(unittest.TestCase):
    def test_actual_tcp_then_tls_completion_and_certificate_failure(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=127.0.0.2",
                    "-addext",
                    "subjectAltName=IP:127.0.0.2",
                ],
                env=non_azure_env(),
                capture_output=True,
                check=True,
            )
            for trusted in (True, False):
                with self.subTest(trusted=trusted):
                    server = subprocess.Popen(
                        [
                            "sudo",
                            "-n",
                            "python3",
                            "-u",
                            "-c",
                            TLS_SERVER,
                            str(cert),
                            str(key),
                        ],
                        env=non_azure_env(),
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    probe = None
                    try:
                        self.assertEqual(server.stdout.readline().strip(), "listening")
                        env = non_azure_env()
                        if trusted:
                            env["SSL_CERT_FILE"] = str(cert)
                        else:
                            env.pop("SSL_CERT_FILE", None)
                        script = endpoint_probe_script("127.0.0.2")
                        self.assertNotIn("timeout=", script)
                        probe = subprocess.Popen(
                            ["bash"],
                            env=env,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                        probe.stdin.write(script)
                        probe.stdin.close()
                        probe.stdin = None
                        self.assertEqual(server.stdout.readline().strip(), "accepted")
                        # TCP acceptance cannot satisfy the real TLS probe.
                        self.assertIsNone(probe.poll())
                        server.stdin.write("handshake\n")
                        server.stdin.flush()
                        out, err = probe.communicate()
                        self.assertEqual(probe.returncode, 0, err)
                        self.assertEqual(
                            out.strip(), "reachable" if trusted else "unreachable"
                        )
                        server_out, server_err = server.communicate()
                        self.assertEqual(server.returncode, 0, server_err)
                        self.assertIn(
                            "TLS established" if trusted else "TLS rejected", server_out
                        )
                    finally:
                        if probe is not None:
                            if probe.poll() is None:
                                probe.kill()
                            probe.communicate()
                        if server.poll() is None:
                            server.terminate()
                        server.communicate()


if __name__ == "__main__":
    unittest.main()
