"""Transport failure behavior without connecting to an endpoint."""
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from cycle_core import Target
from cycle_transport import Transport

class TransportTests(unittest.TestCase):
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

if __name__=='__main__':
    unittest.main()
