"""Real same-process serialization and optional local-guest foreign-slot proof."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
from dataclasses import asdict
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import threading

from azvnet import AzureSession, Remote, RemoteExecutionError


def session():
    return AzureSession(
        tenant_id=os.environ["ARM_TENANT_ID"],
        subscription_id=os.environ["ARM_SUBSCRIPTION_ID"],
        client_id=os.environ["ARM_CLIENT_ID"],
        cli_python=Path("/opt/az/bin/python3"),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--group", required=True)
    parser.add_argument("--vm", required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--foreign-socket", type=Path)
    parser.add_argument("--local-guest-conflict", action="store_true")
    parser.add_argument("--record-write-failure", action="store_true")
    args = parser.parse_args()
    with session() as azure:
        azure.login()
        cache = Path(azure.env["AZURE_CONFIG_DIR"])
        if args.foreign_socket:
            script = f"""python3 - <<'PY'
import socket
with socket.socket(socket.AF_UNIX) as client:
    client.connect({str(args.foreign_socket)!r})
    client.sendall(b'foreign-slot-owned')
    assert client.recv(1) == b'x'
PY"""
            Remote(azure).run(args.group, args.vm, script, capture=True)
            return
        barrier = threading.Barrier(2)

        def work(index):
            remote = Remote(
                azure, record_cleanup=lambda residue: residue.write(args.records)
            )
            barrier.wait()
            return remote.sealed(
                args.group,
                args.vm,
                f"printf 'synthetic-concurrent-{index}\\n'",
                capture=True,
            ).stdout

        remote = Remote(
            azure, record_cleanup=lambda residue: residue.write(args.records)
        )
        if not args.record_write_failure:
            with ThreadPoolExecutor(max_workers=2) as pool:
                jobs = [pool.submit(work, index) for index in range(2)]
                assert [job.result() for job in jobs] == [
                    "synthetic-concurrent-0\n",
                    "synthetic-concurrent-1\n",
                ]
            print(
                "PASS two same-process Remote objects: complete sealed transactions without self-conflict",
                flush=True,
            )
            try:
                remote.sealed(
                    args.group,
                    args.vm,
                    "printf 'synthetic-failure' >&2; exit 23",
                    capture=True,
                )
            except RemoteExecutionError as error:
                assert error.returncode == 23 and "synthetic-failure" in error.stderr
            else:
                raise AssertionError("guest failure became success")
            assert (
                remote.run(args.group, args.vm, "printf released", capture=True).stdout
                == "released"
            )
            print(
                "PASS real guest failure propagates; exception releases VM serialization",
                flush=True,
            )
        else:
            assert args.local_guest_conflict

        if args.local_guest_conflict:
            assert socket.gethostname().casefold() == args.vm.casefold(), (
                "native socket proof requires this exact local guest"
            )
            with tempfile.TemporaryDirectory(
                prefix="azvnet-conflict-", dir="/dev/shm"
            ) as scratch:
                endpoint = Path(scratch) / "slot.sock"
                listener = socket.socket(socket.AF_UNIX)
                listener.bind(str(endpoint))
                listener.listen(1)
                foreign = None
                connection = None
                armed = True
                observed = []
                record_target = args.records
                if args.record_write_failure:
                    record_target = Path(scratch) / "not-a-directory"
                    record_target.touch(mode=0o600)

                def record(residue):
                    observed.append(residue)
                    return residue.write(record_target)

                remote = Remote(azure, record_cleanup=record)

                def observe(event, values):
                    nonlocal armed, foreign, connection
                    if not armed or event != "subprocess.Popen":
                        return
                    command = values[1]
                    if not isinstance(command, (list, tuple)) or command[:4] != [
                        "az",
                        "vm",
                        "run-command",
                        "invoke",
                    ]:
                        return
                    script_arg = command[command.index("--scripts") + 1]
                    body = Path(script_arg[1:]).read_text()
                    if "payload.cms" not in body or "AZVNETOUTPUT" not in body:
                        return
                    # Python's native pre-spawn audit event occurs only after setup
                    # returned. Do not replace any command or execution function.
                    armed = False
                    foreign = subprocess.Popen(
                        [
                            sys.executable,
                            __file__,
                            "--group",
                            args.group,
                            "--vm",
                            args.vm,
                            "--records",
                            str(args.records),
                            "--foreign-socket",
                            str(endpoint),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    connection, _ = listener.accept()
                    assert connection.recv(64) == b"foreign-slot-owned"

                sys.addaudithook(observe)
                before = set(args.records.glob("*.json"))
                try:
                    diagnostics = io.StringIO()
                    try:
                        with redirect_stderr(diagnostics):
                            remote.sealed(
                                args.group,
                                args.vm,
                                "printf never-executed",
                                capture=True,
                            )
                    except subprocess.CalledProcessError as error:
                        assert "Conflict" in (error.stderr or "")
                        assert any(
                            "Cleanup also failed" in note for note in error.__notes__
                        )
                    else:
                        raise AssertionError(
                            "foreign-slot execution unexpectedly succeeded"
                        )
                    print(diagnostics.getvalue(), file=sys.stderr, end="")
                    assert diagnostics.getvalue().count("Code: Conflict") == 2
                    assert len(observed) == 1
                    receipts = set(args.records.glob("*.json")) - before
                    if args.record_write_failure:
                        assert not receipts
                        assert (
                            "Cleanup receipt write also failed:"
                            in diagnostics.getvalue()
                        )
                        data = asdict(observed[0])
                    else:
                        assert len(receipts) == 1
                        receipt = receipts.pop()
                        data = json.loads(receipt.read_text())
                        assert receipt.stat().st_mode & 0o777 == 0o600
                        assert receipt.stat().st_uid == os.getuid()
                    assert (data["group"], data["vm"], data["os"]) == (
                        args.group,
                        args.vm,
                        "Linux",
                    )
                    assert re.fullmatch(r"/run/azvnet-[0-9a-f]{48}", data["directory"])
                    directory = Path(data["directory"])
                    # Exact task receipt only; do not enumerate unrelated guest work.
                    assert directory.is_dir()
                    retained = subprocess.run(
                        ["sudo", "-n", "test", "-f", str(directory / "key.pem")],
                        check=False,
                    )
                    assert retained.returncode == 0
                    if args.record_write_failure:
                        print(
                            "PASS actual receipt I/O failure is visible; primary execution Conflict preserved; nonsecret residue metadata retained in diagnostics",
                            flush=True,
                        )
                    else:
                        print(
                            "PASS setup completed before actual foreign slot acknowledgement; execution and cleanup Conflict; receipt durable; exact task key presence confirmed",
                            flush=True,
                        )
                finally:
                    armed = False
                    if connection is not None:
                        connection.sendall(b"x")
                        connection.close()
                    listener.close()
                    if foreign is not None:
                        out, err = foreign.communicate()
                        assert foreign.returncode == 0, (out, err)
                path = shlex.quote(data["directory"])
                remote.run(
                    args.group,
                    args.vm,
                    f"test -d {path}; rm -rf -- {path}; test ! -e {path}",
                    capture=True,
                )
                assert not directory.exists()
                print(
                    "PASS foreign ARM completion awaited; owner-controlled exact receipt directory recovery verified",
                    flush=True,
                )
    assert not cache.exists()
    print("PASS private CLI cache removed", flush=True)


if __name__ == "__main__":
    main()
