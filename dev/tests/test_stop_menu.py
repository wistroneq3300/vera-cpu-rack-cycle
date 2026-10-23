"""Stop selection never constructs a hardware transport."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Keep the campaign journal out of the real /srv/cycletmp during tests.
os.environ.setdefault('VERA_CAMPAIGN_TMP', tempfile.mkdtemp(prefix='vera-campaign-tmp-'))

from vera_cycle.reporting.cycle_report import journal_path
from vera_cycle.engine.cycle_runtime import (RunRegistry, list_running, process_running,
                                           request_stop, verify_owner)
from vera_cycle.cli import main, stop_menu


class StopMenuTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'runtime'
        self.runs = []
        for number in (1, 2):
            registry = RunRegistry(f'run{number}', self.root)
            registry.register(Path(self.temp.name) / f'output{number}', project='neutrino',
                              cycle_mode='power_cycle', channel='inband', nodes=[f'tray_n{number}'])
            self.runs.append(registry)

    def menu(self, replies):
        answers = iter(replies)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = stop_menu(self.root, lambda _: next(answers))
        self.assertEqual(result, 0)
        return output.getvalue()

    def test_numeric_selection_stops_only_chosen_run(self):
        text = self.menu(['2', '1'])
        self.assertFalse(self.runs[0].requested())
        self.assertTrue(self.runs[1].requested())
        self.assertIn('tray_n2', text)
        self.assertIn('not completion', text)

    def test_invalid_inputs_back_and_exit_do_not_stop(self):
        self.menu(['abc', '9', '1', 'yes', '0', '0'])
        self.assertFalse(any(r.requested() for r in self.runs))

    def test_finished_and_stale_runs_are_excluded(self):
        self.runs[0].finish('COMPLETE')
        with patch('vera_cycle.engine.cycle_runtime.process_running', return_value=False):
            self.assertEqual(list_running(self.root), [])
            with self.assertRaisesRegex(ValueError, 'no longer running'):
                request_stop('run2', self.root)

    def test_linux_reused_pid_is_not_the_original_campaign(self):
        with patch('vera_cycle.engine.cycle_runtime.os.name', 'posix'), patch('vera_cycle.engine.cycle_runtime.os.kill'), patch('vera_cycle.engine.cycle_runtime.process_token', return_value='boot:200'):
            self.assertFalse(process_running(dict(pid=123, process_token='boot:100')))
            self.assertTrue(process_running(dict(pid=123, process_token='boot:200')))

    def test_malformed_registration_does_not_break_menu(self):
        (self.runs[0].path/'owner.json').write_text('[]')
        self.assertEqual(len(list_running(self.root)), 1)

    def test_old_registry_uses_journal_metadata(self):
        path = self.runs[0].path / 'owner.json'
        data = json.loads(path.read_text())
        data.pop('nodes')
        path.write_text(json.dumps(data))
        output = Path(data['output'])
        output.mkdir()
        journal = journal_path(output)
        journal.parent.mkdir(parents=True, exist_ok=True)
        journal.write_text(json.dumps(dict(project='naboo', cycle_mode='reboot',
            channel='outband', nodes=[dict(key='tray_n9', blocked=[])])))
        run = list_running(self.root)[0]
        self.assertEqual(run['nodes'], ['tray_n9'])
        self.assertEqual(run['project'], 'naboo')

    def test_cli_stop_without_id_opens_menu(self):
        with patch('vera_cycle.cli.stop_menu', return_value=0) as menu:
            self.assertEqual(main(['--stop']), 0)
        menu.assert_called_once_with()

    def test_already_requested_is_visible(self):
        request_stop('run1', self.root)
        self.assertIn('STOP REQUESTED', self.menu(['0']))

    def test_run_finishing_before_confirmation_does_not_receive_request(self):
        replies = iter(['1', '1', '0'])
        def read(_):
            answer = next(replies)
            self.runs[0].finish('COMPLETE')
            return answer
        with contextlib.redirect_stdout(io.StringIO()) as output:
            stop_menu(self.root, read)
        self.assertIn('already finished', output.getvalue())
        self.assertFalse(self.runs[0].requested())


class VerifyOwnerTests(unittest.TestCase):
    """A PID from a registration is only signalled when it is still that process.

    Regression: the wrapper used to identify a campaign by UID + cmdline from a
    lock file whose contents outlive the process, so a reused PID (or any other
    neutrino_cycle.py of the same user) could be terminated.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'runtime'
        self.registry = RunRegistry('run1', self.root)
        self.registry.register(Path(self.temp.name) / 'out', project='neutrino',
                               cycle_mode='power_cycle', channel='inband', nodes=['n0'])
        self.owner = json.loads((self.registry.path / 'owner.json').read_text())

    def verify(self, **overrides):
        data = dict(self.owner, **overrides)
        (self.registry.path / 'owner.json').write_text(json.dumps(data))
        return verify_owner('run1', self.root)

    def test_matching_token_is_accepted(self):
        with patch('vera_cycle.engine.cycle_runtime.os.kill'), \
             patch('vera_cycle.engine.cycle_runtime.process_token', return_value=self.owner['process_token']):
            self.assertEqual(self.verify()['pid'], self.owner['pid'])

    def test_reused_pid_is_refused(self):
        with patch('vera_cycle.engine.cycle_runtime.os.kill'), \
             patch('vera_cycle.engine.cycle_runtime.process_token', return_value='other-boot:999'):
            with self.assertRaisesRegex(ValueError, 'PID reuse'):
                self.verify()

    def test_dead_pid_is_refused(self):
        with patch('vera_cycle.engine.cycle_runtime.os.kill', side_effect=ProcessLookupError):
            with self.assertRaisesRegex(ValueError, 'no longer running'):
                self.verify()

    def test_missing_token_fails_closed(self):
        with patch('vera_cycle.engine.cycle_runtime.os.kill'):
            with self.assertRaisesRegex(ValueError, 'no start token'):
                self.verify(process_token=None)

    def test_unreadable_token_fails_closed(self):
        with patch('vera_cycle.engine.cycle_runtime.os.kill'), \
             patch('vera_cycle.engine.cycle_runtime.process_token', return_value=None):
            with self.assertRaisesRegex(ValueError, 'unreadable'):
                self.verify()

    def test_other_controller_registration_is_refused(self):
        with patch('vera_cycle.engine.cycle_runtime.os.kill'):
            with self.assertRaisesRegex(ValueError, 'registered on'):
                self.verify(host='some-other-host')

    def test_finished_run_is_refused(self):
        self.registry.finish('COMPLETE')
        self.owner = json.loads((self.registry.path / 'owner.json').read_text())
        with patch('vera_cycle.engine.cycle_runtime.os.kill'):
            with self.assertRaisesRegex(ValueError, 'already finished'):
                self.verify()
