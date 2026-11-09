"""One executing responder per state directory.

Two responders watching the same findings both plan, both ask, and both act on the same incident: a key is deactivated
twice, a replacement key fails with LimitExceeded, two outcomes are written, and because the audit log's lock only covers
one process the hash chain breaks. That happened on 2026-11-08 after `make respond-up` was run several times (it starts a
new process and overwrites the pid file, so the earlier ones stayed alive).

The lock is an OS file lock (flock), so it is released when the process dies, however it dies. The lock file lives in the
system temp directory, not in the state directory: the state directory may be on a network or Windows mount where flock is
not reliable."""
from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

try:
    import fcntl
except ImportError:          # Windows: no flock. The make targets still guard against a second start.
    fcntl = None


def lock_path(name: str, key) -> Path:
    digest = hashlib.sha256(str(Path(key).resolve()).encode()).hexdigest()[:12]
    return Path(tempfile.gettempdir()) / f"aegis-{name}-{digest}.lock"


def acquire(name: str, key):
    """Return (handle, holder_pid). handle is None if someone else holds it. Keep the handle alive for the life of the process."""
    if fcntl is None:
        return object(), ""
    fh = open(lock_path(name, key), "a+")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.seek(0)
        holder = fh.read().strip()
        fh.close()
        return None, holder or "unknown"
    fh.seek(0)
    fh.truncate()
    fh.write(str(os.getpid()))
    fh.flush()
    return fh, ""
