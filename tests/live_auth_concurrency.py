"""Real cold AzureSession authentication with native audit/thread coordination."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import threading

from azvnet import AzureSession
from azvnet.auth import CLI_STDIN_PROGRAM


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-race", action="store_true")
    args = parser.parse_args()
    first_verifying = threading.Event()
    second_entering = threading.Event()
    first_finished = threading.Event()
    caches = set()
    logins = []
    parallel = threading.Barrier(2)
    phase = "cold"

    with AzureSession(
        tenant_id=os.environ["ARM_TENANT_ID"],
        subscription_id=os.environ["ARM_SUBSCRIPTION_ID"],
        client_id=os.environ["ARM_CLIENT_ID"],
        cli_python=Path("/opt/az/bin/python3"),
    ) as session:

        def audit(event, values):
            if event != "subprocess.Popen":
                return
            command = values[1]
            if not isinstance(command, (tuple, list)):
                return
            worker = threading.current_thread().name
            if CLI_STDIN_PROGRAM in command:
                caches.add(Path(values[3]["AZURE_CONFIG_DIR"]))
                logins.append(worker)
                if worker == "auth-second":
                    second_entering.set()
                    if args.baseline_race:
                        first_finished.wait()
            elif command[:3] == ["az", "account", "show"]:
                if phase == "parallel":
                    parallel.wait()
                elif worker == "auth-first":
                    first_verifying.set()
                    second_entering.wait()

        sys.addaudithook(audit)

        def first():
            threading.current_thread().name = "auth-first"
            try:
                session.login()
                return "authenticated"
            except Exception as error:
                if not args.baseline_race:
                    raise
                return type(error).__name__
            finally:
                first_finished.set()

        def second():
            threading.current_thread().name = "auth-second"
            first_verifying.wait()
            if not args.baseline_race:

                def profile(frame, event, arg):
                    if (
                        event == "call"
                        and frame.f_code.co_name == "login"
                        and frame.f_locals.get("self") is session
                    ):
                        second_entering.set()

                sys.setprofile(profile)
            try:
                session.login()
                return "authenticated"
            finally:
                sys.setprofile(None)

        with ThreadPoolExecutor(max_workers=2) as pool:
            one, two = pool.submit(first), pool.submit(second)
            outcomes = [one.result(), two.result()]
        if args.baseline_race:
            assert outcomes == ["CalledProcessError", "authenticated"], outcomes
            assert len(logins) == 2 and len(caches) == 2
            print(
                "RED actual cold-login cache race: first verification failed; second authenticated"
            )
        else:
            assert outcomes == ["authenticated", "authenticated"], outcomes
            assert len(logins) == 1 and len(caches) == 1
            print(
                "PASS two real cold callers authenticate using exactly one private cache/login"
            )
        phase = "parallel"

        def query():
            document = session.json("account", "show")
            assert document["id"].lower() == session.subscription_id.lower()
            assert document["tenantId"].lower() == session.tenant_id.lower()

        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(query) for _ in range(2)]
            for job in jobs:
                job.result()
        print(
            "PASS authenticated commands reach native subprocess boundary concurrently; identities checked"
        )
    assert caches and all(not cache.exists() for cache in caches)
    print("PASS all observed private CLI caches removed")
    print(
        json.dumps(
            {
                "outcomes": outcomes,
                "login_processes": len(logins),
                "cache_count": len(caches),
            }
        )
    )


if __name__ == "__main__":
    main()
