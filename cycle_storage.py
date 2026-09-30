"""Output serialization and live-owner checks shared by runner and rebuild."""
from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import socket
import time


def windows_process(pid):
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:  # no such PID
            return False, None
        raise RuntimeError('Cannot verify report owner process')
    try:
        code = wintypes.DWORD()
        times = [wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)) or not kernel.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
            raise RuntimeError('Cannot verify report owner process identity')
        token = str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)
        return code.value == 259, token
    finally:
        kernel.CloseHandle(handle)


def writer_identity():
    from cycle_runtime import process_token
    token = windows_process(os.getpid())[1] if os.name == 'nt' else process_token(os.getpid())
    return dict(pid=os.getpid(), process_token=token, host=socket.gethostname())


def owner_alive(owner):
    from cycle_runtime import process_token
    if owner.get('host', socket.gethostname()) != socket.gethostname():
        raise RuntimeError('Cannot verify a RUNNING owner on another controller; rebuild on the source controller after it stops')
    pid = int(owner['pid'])
    if pid <= 0:
        raise RuntimeError('Invalid report owner PID')
    if os.name == 'nt':
        alive, token = windows_process(pid)
    else:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError as exc:
            raise RuntimeError('Cannot verify report owner; rebuild refused') from exc
        alive, token = True, process_token(pid)
    expected = owner.get('process_token')
    if alive and expected and token is None:
        raise RuntimeError('Cannot verify report owner start token')
    return alive and (not expected or token == expected)


@contextmanager
def report_writer_lock(root, wait=False):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    # Never unlink a lock file: competing processes must lock the same inode.
    path = root / '.report-writer.lock'
    with path.open('a+b') as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b' ')
            stream.flush()
        stream.seek(0)
        deadline = time.monotonic() + (30 if wait else 0)
        while True:
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Campaign output writer is busy; retry after it stops') from exc
                time.sleep(.05)
        try:
            yield
        finally:
            if os.name == 'nt':
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def reject_live_rebuild(root, campaign, runtime_root=None):
    from cycle_runtime import shared_root
    root = Path(root).resolve()
    if campaign.get('state') == 'RUNNING' and campaign.get('writer_owner') and owner_alive(campaign['writer_owner']):
        raise RuntimeError('Live campaign owner is still running; rebuild refused')
    runtime_root = Path(runtime_root) if runtime_root is not None else shared_root()
    for path in runtime_root.glob('run-*/owner.json'):
        try:
            owner = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            # The matching registration must be readable; unrelated users may
            # have private directories. Journal writer identity is also checked.
            if path.parent.name == 'run-' + campaign['run_id']:
                raise RuntimeError('Cannot verify campaign registration; rebuild refused')
            continue
        if Path(owner.get('output', '')).resolve() == root and owner.get('state') == 'RUNNING' and owner_alive(owner):
            raise RuntimeError('Live campaign registration exists; rebuild refused')
