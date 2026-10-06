"""Transport failure behavior without connecting to an endpoint."""
import tempfile
import os
import stat
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from cycle_core import Target
from cycle_transport import Transport


def _fake_curl(directory, status, body='{"Members": []}', exit_code=0):
    """Write a curl stub that always prints ``body`` and ``status`` then exits.

    curl with -s and no -f exits 0 even for a 4xx/5xx response, so the stub
    mirrors that: the HTTP status is only visible through the ``-w`` marker.
    """
    path = Path(directory) / 'curl'
    script = (
        "#!/usr/bin/env sh\n"
        "cat <<'VERA_BODY'\n"
        f"{body}\n"
        "VERA_BODY\n"
        f"printf '\\n__VERA_HTTP_STATUS__:{status}'\n"
        f"exit {exit_code}\n"
    )
    path.write_text(script, encoding='utf-8')
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return directory


class RedfishHTTPStatusTests(unittest.TestCase):
    """P1-3: a completed HTTP exchange with a 4xx/5xx status is a failure."""

    def _run(self, status, body='{"Members": []}', exit_code=0):
        with tempfile.TemporaryDirectory() as temp:
            directory = _fake_curl(temp, status, body, exit_code)
            transport = Transport({}, Path(temp) / 'known')
            old = os.environ['PATH']
            os.environ['PATH'] = directory + os.pathsep + old
            try:
                result = transport._redfish(['https://bmc/redfish/v1/Systems'], 5)
            finally:
                os.environ['PATH'] = old
            return result

    def test_http_200_is_success(self):
        result = self._run(200)
        self.assertEqual(result.code, 0)
        self.assertEqual(result.http_status, 200)

    def test_http_204_clear_is_success(self):
        result = self._run(204, body='')
        self.assertEqual(result.code, 0)
        self.assertEqual(result.http_status, 204)

    def test_http_4xx_5xx_are_failures(self):
        for status in (400, 401, 404, 409, 500, 503):
            with self.subTest(status=status):
                result = self._run(status)
                self.assertNotEqual(result.code, 0)
                self.assertEqual(result.state, 'HTTP_ERROR')
                self.assertEqual(result.http_status, status)
                self.assertGreaterEqual(result.code, 400)

    def test_http_error_body_is_not_treated_as_success(self):
        # A 500 with a JSON-looking body must still be a failure.
        result = self._run(500, body='{"Members": [{"Id": "1"}]}')
        self.assertNotEqual(result.code, 0)
        self.assertEqual(result.http_status, 500)

    def test_timeout_is_a_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            transport = Transport({}, Path(temp) / 'known')
            def timeout(*args, **kwargs):
                raise subprocess_timeout()
            from cycle_transport import subprocess as tp_subprocess
            with patch.object(tp_subprocess, 'run', side_effect=timeout):
                result = transport._redfish(['https://bmc/redfish/v1/Systems'], 5)
            self.assertEqual(result.code, 124)
            self.assertEqual(result.state, 'RESPONSE_LOST')


def subprocess_timeout():
    import subprocess
    return subprocess.TimeoutExpired('curl', 5)


class TransportTests(unittest.TestCase):
    def test_none_password_can_use_passwordless_sudo(self):
        channel=MagicMock()
        channel.recv_ready.return_value=False
        channel.exit_status_ready.return_value=True
        channel.recv_exit_status.return_value=0
        client=MagicMock()
        client.get_transport.return_value.open_session.return_value=channel
        with tempfile.TemporaryDirectory() as temp:
            transport=Transport({'os':None},Path(temp))
            with patch.object(transport,'_connect',return_value=client), patch.dict(os.environ,{'OS_USER':'operator'}):
                result=transport.ssh(Target('tray','n1','192.0.2.1','192.0.2.2'),'os','id -u',sudo=True)
            self.assertEqual(result.code,0,result.output)
            channel.sendall.assert_called_once_with(b'\n')

    def test_none_password_produces_string_ipmi_environment(self):
        def execute(*args,**kwargs):
            self.assertEqual(kwargs['env']['IPMI_PASSWORD'],'')
            return MagicMock(returncode=1,stdout='',stderr='Authentication failed')
        with tempfile.TemporaryDirectory() as temp:
            transport=Transport({'bmc':None},Path(temp))
            with patch('cycle_transport.subprocess.run',side_effect=execute):
                result=transport.oob(Target('tray','n1','192.0.2.1','192.0.2.2'),'power status')
            self.assertEqual(result.code,1)

    def test_stalled_exec_ack_is_bounded_and_ambiguous(self):
        closed=threading.Event()
        class Channel:
            def set_combine_stderr(self,*args): pass
            def settimeout(self,*args): pass
            def exec_command(self,cmd):
                closed.wait(3)
                raise EOFError('connection closed while awaiting acknowledgement')
        class Client:
            def close(self): closed.set()
            def get_transport(self): return self
            def open_session(self,**kwargs): return Channel()
        with tempfile.TemporaryDirectory() as temp:
            transport=Transport({},Path(temp))
            with patch.object(transport,'_connect',return_value=Client()):
                start=time.monotonic()
                result=transport.ssh(Target('tray','n1','192.0.2.1','192.0.2.2'), 'os','reboot',timeout=.1)
                self.assertLess(time.monotonic()-start,1)
                self.assertEqual(result.state,'RESPONSE_LOST')

    def test_connect_failure_is_not_issued(self):
        with tempfile.TemporaryDirectory() as temp:
            transport=Transport({},Path(temp))
            with patch.object(transport,'_connect',side_effect=ConnectionError('offline')):
                result=transport.ssh(Target('tray','n1','192.0.2.1','192.0.2.2'),'os','reboot')
                self.assertEqual(result.state,'NOT_ISSUED')

    def test_tail_is_drained_after_exit_status_is_ready(self):
        # Regression: exit_status_ready() can flip true while the last block of
        # stdout is still in flight; the reader must not drop that tail (it holds
        # the trailing RESULT| marker that large outputs such as the hardware
        # check rely on).
        tail=b'\nRESULT|FAIL\n'
        class Channel:
            def __init__(self):
                self._sent=False
                self._started=None
            def set_combine_stderr(self,*args): pass
            def settimeout(self,*args): pass
            def exec_command(self,cmd): self._started=time.monotonic()
            def sendall(self,*args): pass
            def shutdown_write(self): pass
            def exit_status_ready(self): return True
            def recv_exit_status(self): return 1
            def recv_ready(self):
                if self._started is None: return False
                # Data only becomes readable a short moment after exit is ready.
                return not self._sent and time.monotonic()-self._started >= .1
            def recv(self,n):
                self._sent=True
                return tail
        class Client:
            def close(self): pass
            def get_transport(self): return self
            def open_session(self,**kwargs): return self._channel
        client=Client(); client._channel=Channel()
        with tempfile.TemporaryDirectory() as temp:
            transport=Transport({},Path(temp))
            with patch.object(transport,'_connect',return_value=client):
                result=transport.ssh(Target('tray','n1','192.0.2.1','192.0.2.2'),'os','echo',timeout=5)
        self.assertEqual(result.code,1)
        self.assertIn('RESULT|FAIL',result.output)

if __name__=='__main__':
    unittest.main()
