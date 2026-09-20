"""Nonsecret receipts for operator-controlled recovery of failed guest cleanup."""

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import stat
import tempfile

from .auth import AzvnetError


@dataclass(frozen=True)
class CleanupResidue:
    subscription_id: str
    group: str
    vm: str
    directory: str
    os: str
    invocation: str
    certificate_subject: str | None = None

    def write(self, directory: Path) -> Path:
        """Atomically publish a private receipt without replacing an existing record."""
        missing = []
        ancestor = directory
        while not ancestor.exists():
            missing.append(ancestor)
            ancestor = ancestor.parent
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = directory.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise AzvnetError("residue directory must be current-user-owned mode-0700")
        for created in reversed(missing):
            _sync_directory(created.parent)
        # The name is generated locally, never derived from remote output or a VM name.
        with tempfile.NamedTemporaryFile(
            mode="w", dir=directory, encoding="utf-8"
        ) as staged:
            target = directory / (Path(staged.name).name + ".json")
            json.dump(asdict(self), staged, indent=2)
            staged.write("\n")
            staged.flush()
            os.fsync(staged.fileno())
            os.link(staged.name, target)
        _sync_directory(directory)
        return target


def _sync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
