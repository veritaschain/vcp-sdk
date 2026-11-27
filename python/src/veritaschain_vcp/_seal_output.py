"""Publish the two files produced by the signing CLI."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class _RecoveryRequired(OSError):
    """Preserve staged files for manual recovery after a second I/O failure."""


@contextmanager
def _stage(target: Path, content: str) -> Iterator[Path]:
    # Each destination has its own exclusive staging directory. Two seal
    # processes sharing either output must not interleave their replacements.
    digest = hashlib.sha256(os.fsencode(target.name.casefold())).hexdigest()
    folder = target.parent / (".vcp-seal-" + digest)
    try:
        folder.mkdir(mode=0o700)
    except FileExistsError as error:
        raise OSError(f"seal staging directory already in use: {folder}") from error

    keep_for_recovery = False
    try:
        try:
            mode = target.stat().st_mode
        except FileNotFoundError:
            mode = None
        if mode is not None:
            if not stat.S_ISREG(mode):
                raise OSError(f"seal output is not a regular file: {target}")
            # Check write access before replacing an existing file.
            with target.open("rb+"):
                pass

        staged = folder / "new"
        staged.write_text(content, encoding="utf-8")
        if mode is not None:
            staged.chmod(stat.S_IMODE(mode))
        yield staged
    except _RecoveryRequired:
        keep_for_recovery = True
        raise
    finally:
        if not keep_for_recovery:
            shutil.rmtree(folder)


def publish_seal_outputs(events: Path, event_text: str, anchor: Path, anchor_text: str) -> None:
    # Follow output symlinks just as opening the output files for writing did.
    events, anchor = events.resolve(), anchor.resolve()
    with _stage(events, event_text) as event_file, _stage(anchor, anchor_text) as anchor_file:
        original = event_file.parent / "previous"
        had_events = events.exists()
        if had_events:
            shutil.copy2(events, original)
        os.replace(event_file, events)
        try:
            os.replace(anchor_file, anchor)
        except OSError as publish_error:
            try:
                if had_events:
                    os.replace(original, events)
                else:
                    events.unlink()
            except OSError as rollback_error:
                raise _RecoveryRequired(
                    f"could not publish {anchor} ({publish_error}) or restore {events} "
                    f"({rollback_error}); recovery files in {event_file.parent} and {anchor_file.parent}"
                ) from rollback_error
            raise
