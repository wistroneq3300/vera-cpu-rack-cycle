"""Lock contention uses a separate process, not only objects in one process."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cycle_core import Target
from cycle_runtime import EndpointLocks


class ProcessLocks(unittest.TestCase):
    def test_overlap_blocked_other_node_allowed_then_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'locks'
            held = Target('tray', 'n1', '192.0.2.1', '192.0.2.2', 'bmc', 'os')
            locks = EndpointLocks(root)
            locks.acquire(held, 'owner-campaign')
            code = '''
import sys
from cycle_core import Target
from cycle_runtime import EndpointLocks
locks = EndpointLocks(sys.argv[1])
t = Target('other-tray', 'different-label', sys.argv[2], sys.argv[3], 'bmc', 'os')
try:
    locks.acquire(t, 'second-campaign')
except RuntimeError as exc:
    print(exc)
    sys.exit(9)
finally:
    locks.close()
'''
            def run(first, second):
                return subprocess.run([sys.executable, '-c', code, str(root), first, second],
                                      capture_output=True, text=True, timeout=15, check=False)
            try:
                conflict = run('192.0.2.1', '192.0.2.9')
                self.assertEqual(conflict.returncode, 9, conflict.stderr)
                self.assertIn('locked by another campaign', conflict.stdout)
                self.assertEqual(run('192.0.2.3', '192.0.2.4').returncode, 0)
            finally:
                locks.close()
            data = json.loads(next(root.glob('endpoint-*.lock')).read_text())
            self.assertIn('user', data)
            self.assertEqual(run('192.0.2.1', '192.0.2.2').returncode, 0)

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'getuid') and os.getuid() == 0,
                         'Cross-UID test needs a Linux root test environment')
    def test_existing_shared_lock_can_be_opened_by_another_uid(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o755)
            root = Path(tmp) / 'locks'
            target = Target('tray', 'n1', '192.0.2.1', '192.0.2.2', 'bmc', 'os')
            owner = EndpointLocks(root)
            owner.acquire(target, 'owner')
            # Fork retains imported modules; drop access before reopening files.
            def child(expect_blocked):
                pid = os.fork()
                if pid == 0:
                    owner.close()
                    os.setgid(65534)
                    os.setuid(65534)
                    contender = EndpointLocks(root)
                    try:
                        contender.acquire(target, 'other-user')
                        status = 1 if expect_blocked else 0
                    except RuntimeError:
                        status = 0 if expect_blocked else 1
                    except OSError:
                        status = 2
                    finally:
                        contender.close()
                    os._exit(status)
                self.assertEqual(os.waitpid(pid, 0)[1], 0)
            try:
                child(True)
            finally:
                owner.close()
            child(False)
