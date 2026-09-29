"""Per-endpoint interprocess locks and owner-only graceful stop requests."""
from __future__ import annotations

import hashlib
import getpass
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
                # Open existing shared files without O_CREAT: Linux protected_regular
                # rejects O_CREAT on another user's file in a sticky directory.
                flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                try:
                    fd = os.open(path, flags)
                except FileNotFoundError:
                    try:
                        fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o666)
                    except FileExistsError:
                        fd = os.open(path, flags)
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    os.close(fd)
                    raise RuntimeError(f"Unsafe endpoint lock: {path}")
                handle = os.fdopen(fd, "r+b", buffering=0)
                if os.name != "nt" and os.fstat(fd).st_uid == os.getuid():
                    os.fchmod(fd, 0o666)
                try:
                    if os.name == "nt":
                        # Windows-only module; Linux uses flock below.
                        import msvcrt
                        if path.stat().st_size == 0:
                            handle.write(b" ")
                        handle.seek(0)
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        # POSIX-only module; keep Windows offline tests importable.
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    owner = ""
                    try:
                        handle.seek(0)
                        data = json.loads(handle.read(4096))
                        owner = f" (run {data['run_id']}, node {data['node']}, user {data.get('user', 'unknown')})"
                    except (OSError, ValueError, KeyError):
                        pass
                    handle.close()
                    raise RuntimeError(f"Endpoint {addr} is locked by another campaign{owner}; no commands sent to this target") from exc
                acquired.append(handle)
                handle.seek(0)
                handle.write(json.dumps(dict(run_id=run_id, node=target.key, user=getpass.getuser(), pid=os.getpid(), utc=now())).encode())
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

    def register(self, output, **metadata):
        write_json(self.path / "owner.json", dict(**metadata, run_id=self.run_id, pid=os.getpid(),
                   output=str(output), state="RUNNING", utc=now(), process_token=process_token(os.getpid())))

    def requested(self):
        return (self.path / "stop.request").exists()

    def finish(self, state):
        path = self.path / "owner.json"
        data = json.loads(path.read_text())
        data.update(state=state, finished=now())
        write_json(path, data)

def process_token(pid):
    """Linux process start identity, including boot identity to reject PID reuse."""
    if os.name == 'nt':
        return None
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return Path('/proc/sys/kernel/random/boot_id').read_text().strip() + ':' + fields[19]
    except (OSError, IndexError):
        return None


def process_running(data):
    if os.name == 'nt':
        # Windows os.kill(pid, 0) is not a safe POSIX liveness probe.
        return True
    try:
        pid = int(data['pid'])
        if pid <= 0:
            return False
        os.kill(pid, 0)
    except (ProcessLookupError, ValueError, KeyError, TypeError):
        return False
    except PermissionError:
        return False
    token = data.get('process_token')
    return not token or token == process_token(pid)


def list_running(root=None):
    """Read only the current user's active registrations; never contact nodes."""
    root = Path(root) if root is not None else shared_root()
    runs = []
    for path in root.glob('run-*'):
        try:
            if path.is_symlink() or not path.is_dir():
                continue
            if os.name != 'nt' and path.stat().st_uid != os.getuid():
                continue
            data = json.loads((path / 'owner.json').read_text(encoding='utf-8'))
            if not isinstance(data, dict) or not isinstance(data.get('output'), str):
                continue
            if data.get('state') != 'RUNNING' or not process_running(data):
                continue
            data['run_id'] = path.name.removeprefix('run-')
            # Older registrations stored display metadata only in the journal.
            if 'nodes' not in data:
                try:
                    campaign = json.loads((Path(data['output']) / 'campaign.json').read_text(encoding='utf-8'))
                    data.update(project=campaign.get('project', 'Unknown'),
                                cycle_mode=campaign.get('cycle_mode', 'Unknown'),
                                channel=campaign.get('channel', 'Unknown'),
                                nodes=[n['key'] for n in campaign.get('nodes', []) if not n.get('blocked')])
                except (OSError, ValueError, KeyError, TypeError):
                    pass
            data['stop_requested'] = (path / 'stop.request').exists()
            if not isinstance(data.get('nodes', []), list) or not all(isinstance(n, str) for n in data.get('nodes', [])):
                data['nodes'] = []
            runs.append(data)
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return sorted(runs, key=lambda r: (r.get('utc', ''), r['run_id']))


def request_stop(run_id, root=None):
    if not re.fullmatch(r"[A-Za-z0-9_.+\-]+", run_id):
        raise ValueError("Invalid Run ID")
    path = (Path(root) if root is not None else shared_root()) / ("run-" + run_id)
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"Unknown Run ID: {run_id}")
    if os.name != "nt" and path.stat().st_uid != os.getuid():
        raise PermissionError("Only the campaign owner can request a stop")
    data = json.loads((path / "owner.json").read_text())
    if data["state"] != "RUNNING":
        raise ValueError(f"Campaign already finished: {data['state']}")
    if not process_running(data):
        raise ValueError('Campaign process is no longer running; no stop request sent')
    (path / "stop.request").write_text(now(), encoding="ascii")
    return data
