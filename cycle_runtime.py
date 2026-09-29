"""Per-endpoint interprocess locks and owner-only graceful stop requests."""
from __future__ import annotations
import hashlib
import ipaddress
import json
import os
import re
import stat
from pathlib import Path
from cycle_core import now, write_json

def shared_root():
    return Path(os.environ.get("VERA_RUNTIME_DIR", "/tmp/vera-cycle-runtime" if os.name != "nt" else str(Path(os.environ["TEMP"]) / "vera-cycle-runtime")))

def prepare_root(root):
    try:
        root.mkdir(mode=0o1777, parents=False)
    except FileExistsError:
        pass
    else:
        if os.name != "nt":
            root.chmod(0o1777)
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError(f"Unsafe runtime directory: {root}")
    if os.name != "nt" and stat.S_IMODE(root.stat().st_mode) != 0o1777:
        raise RuntimeError(f"Runtime directory must have mode 1777: {root}. Ask its owner to correct permissions.")

class EndpointLocks:
    def __init__(self, root=None):
        self.root = Path(root) if root is not None else shared_root()
        prepare_root(self.root)
        self.handles = []

    def acquire(self, target, run_id):
        acquired = []
        try:
            for addr in sorted({str(ipaddress.ip_address(ip)) for _, ip, _ in target.endpoints()}):
                path = self.root / ("endpoint-" + hashlib.sha256(addr.encode()).hexdigest() + ".lock")
                fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o666)
                handle = os.fdopen(fd, "r+b", buffering=0)
                if os.name != "nt" and os.fstat(fd).st_uid == os.getuid():
                    os.fchmod(fd, 0o666)
                try:
                    if os.name == "nt":
                        import msvcrt
                        if path.stat().st_size == 0:
                            handle.write(b" ")
                        handle.seek(0)
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    handle.close()
                    raise RuntimeError(f"Endpoint {addr} is locked by another campaign") from exc
                acquired.append(handle)
                handle.seek(0)
                handle.write(json.dumps(dict(run_id=run_id, node=target.key, pid=os.getpid(), utc=now())).encode())
                handle.truncate()
            self.handles.extend(acquired)
        except BaseException:
            for handle in acquired:
                handle.close()
            raise

    def close(self):
        for handle in self.handles:
            handle.close()
        self.handles.clear()

class RunRegistry:
    def __init__(self, run_id, root=None):
        self.root = Path(root) if root is not None else shared_root()
        prepare_root(self.root)
        self.path = self.root / ("run-" + run_id)
        self.path.mkdir(mode=0o700)
        self.run_id = run_id

    def register(self, output):
        write_json(self.path / "owner.json", dict(run_id=self.run_id, pid=os.getpid(), output=str(output), state="RUNNING", utc=now()))

    def requested(self):
        return (self.path / "stop.request").exists()

    def finish(self, state):
        path = self.path / "owner.json"
        data = json.loads(path.read_text())
        data.update(state=state, finished=now())
        write_json(path, data)

def request_stop(run_id, root=None):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", run_id):
        raise ValueError("Invalid Run ID")
    path = (Path(root) if root is not None else shared_root()) / ("run-" + run_id)
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"Unknown Run ID: {run_id}")
    if os.name != "nt" and path.stat().st_uid != os.getuid():
        raise PermissionError("Only the campaign owner can request a stop")
    data = json.loads((path / "owner.json").read_text())
    if data["state"] != "RUNNING":
        raise ValueError(f"Campaign already finished: {data['state']}")
    (path / "stop.request").write_text(now(), encoding="ascii")
    return data
