"""Stopped recovery integrity and controlled live-writer races; no rack access."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from cycle_core import issue, now, write_json
from cycle_engine import new_record
from cycle_report import rebuild, status, write_reports
from cycle_runtime import RunRegistry
from neutrin_cycle import main
from test_cycle import target


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'output'
        self.runtime = Path(self.tmp.name)/'runtime'
        pre = new_record('PRE')
        pre.update(status='PASS', finished=now())
        loop = new_record('LOOP 1')
        loop.update(loop=1, post_complete=True, boot_confirmed=True, valid_cycle=True, status='FAIL', finished=now(),
                    issues=[issue('SENSOR_CRITICAL', 'CPU Temp', 'Historical sensor failure')],
                    action=[dict(command='power cycle', role='oob', state='SENT', code=0)])
        self.data = dict(run_id='run2-test', project='neutrino', started=now(), finished=now(),
                         state='COMPLETE', stop_reason='Limit reached', cycle_mode='power_cycle', channel='outband',
                         limits=dict(loops=1, hours=0), script_sha256='a'*64,
                         nodes=[dict(key='tray1_n1', target=target().__dict__, pre=pre, loops=[loop], completed=1,
                                     attempts=1, boot_confirmed=1, valid_cycles=1, blocked=[], active=True, stop_reason='')])
        self.save()

    def save(self):
        for node in self.data['nodes']:
            write_json(self.root/node['key']/'pre_report.json', node['pre'])
            for loop in node['loops']:
                write_json(self.root/node['key']/f"loop{loop['loop']:04d}"/'report.json', loop)
        write_reports(self.root, self.data)

    def test_missing_loop_keeps_journal_fail_and_counts(self):
        (self.root/'tray1_n1/loop0001/report.json').unlink()
        result = rebuild(self.root)
        self.assertEqual(status(result)['health'], 'FAIL')
        self.assertEqual(result['nodes'][0]['completed'], 1)
        self.assertEqual(len(result['nodes'][0]['loops']), 1)
        self.assertIn('SENSOR_CRITICAL', [i['code'] for i in result['nodes'][0]['loops'][0]['issues']])
        self.assertTrue(result['nodes'][0]['recovery_notes'])
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertEqual(json.loads((self.root/'campaign.json').read_text())['nodes'][0]['completed'], 1)

    def test_journal_only_and_repeat_rebuild_is_idempotent(self):
        (self.root/'tray1_n1/loop0001/report.json').unlink()
        (self.root/'tray1_n1/pre_report.json').unlink()
        first = rebuild(self.root)
        second = rebuild(self.root)
        self.assertEqual(first, second)
        self.assertEqual(status(second)['health'], 'FAIL')
        self.assertEqual(second['nodes'][0]['completed'], 1)

    def test_corrupt_independent_json_keeps_primary_history(self):
        (self.root/'tray1_n1/loop0001/report.json').write_text('{broken')
        result = rebuild(self.root)
        self.assertEqual(status(result)['health'], 'FAIL')
        self.assertEqual(result['nodes'][0]['completed'], 1)
        self.assertIn('invalid independent record', str(result['nodes'][0]['recovery_notes']))

    def test_newer_partial_does_not_erase_finished_fail(self):
        original = self.data['nodes'][0]['loops'][0]
        original['revision'] = 10
        self.save()
        partial = copy.deepcopy(original)
        partial.update(revision=11, finished=None, status='PENDING', post_complete=False, valid_cycle=False,
                       issues=[issue('COLLECTION_FAILED', 'sensor', 'New partial evidence')])
        write_json(self.root/'tray1_n1/loop0001/report.json', partial)
        result = rebuild(self.root)
        loop = result['nodes'][0]['loops'][0]
        self.assertEqual({i['code'] for i in loop['issues']}, {'SENSOR_CRITICAL', 'COLLECTION_FAILED'})
        self.assertEqual(len(loop['recovery_versions']), 2)
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertEqual(result, rebuild(self.root))

    def test_complete_superset_can_finish_partial_journal(self):
        complete = copy.deepcopy(self.data['nodes'][0]['loops'][0])
        complete['revision'] = 12
        self.data['state'] = 'RUNNING'
        self.data['nodes'][0]['loops'][0].update(revision=10, finished=None, post_complete=False, valid_cycle=False, status='PENDING')
        write_reports(self.root, self.data)
        write_json(self.root/'tray1_n1/loop0001/report.json', complete)
        result = rebuild(self.root)
        self.assertEqual(result['nodes'][0]['completed'], 1)
        self.assertEqual(status(result)['health'], 'FAIL')
        self.assertEqual(result['nodes'][0]['loops'][0]['revision'], 12)

    def test_multinode_loss_retains_both_histories(self):
        second = copy.deepcopy(self.data['nodes'][0])
        second['key'] = 'tray1_n2'
        second['target'] = target('n2', offset=2).__dict__
        self.data['nodes'].append(second)
        self.save()
        (self.root/'tray1_n1/loop0001/report.json').unlink()
        result = rebuild(self.root)
        self.assertEqual([n['completed'] for n in result['nodes']], [1, 1])
        self.assertEqual(sum(i['code'] == 'SENSOR_CRITICAL' for i in status(result)['issues']), 2)

    def test_complete_zero_loop_and_missing_count_cannot_be_pass(self):
        self.data['nodes'][0]['loops'] = []
        (self.root/'tray1_n1/loop0001/report.json').unlink()
        write_reports(self.root, self.data)
        result = rebuild(self.root)
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertEqual(status(result)['health'], 'FAIL')
        self.assertEqual(result['nodes'][0]['recovery_original_counters']['completed'], 1)

    def test_live_cli_refuses_and_preserves_journal_bytes(self):
        self.data['state'] = 'RUNNING'
        write_reports(self.root, self.data)
        registry = RunRegistry(self.data['run_id'], self.runtime)
        registry.register(self.root)
        before = (self.root/'campaign.json').read_bytes()
        with patch.dict(os.environ, {'VERA_RUNTIME_DIR': str(self.runtime)}), contextlib.redirect_stderr(io.StringIO()):
            code = main(['--report', str(self.root)])
        self.assertEqual(code, 2)
        self.assertEqual((self.root/'campaign.json').read_bytes(), before)
        self.assertEqual(json.loads((registry.path/'owner.json').read_text())['state'], 'RUNNING')

    def test_dead_real_owner_allows_recovery(self):
        code = '''
import json, sys
from pathlib import Path
from cycle_runtime import RunRegistry
from cycle_storage import writer_identity
from cycle_core import write_json
root=Path(sys.argv[1]); path=root/'campaign.json'
data=json.loads(path.read_text()); data['state']='RUNNING'; data['writer_owner']=writer_identity()
write_json(path,data)
RunRegistry(data['run_id'],sys.argv[2]).register(root)
'''
        subprocess.run([sys.executable, '-c', code, str(self.root), str(self.runtime)], check=True, timeout=15)
        result = rebuild(self.root, runtime_root=self.runtime)
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertEqual(result['nodes'][0]['completed'], 1)
        self.assertEqual(status(result)['health'], 'FAIL')

    def test_runner_rebuild_race_cannot_steal_temp_file(self):
        self.data['state'] = 'RUNNING'
        write_reports(self.root, self.data)
        registry = RunRegistry(self.data['run_id'], self.runtime)
        registry.register(self.root)
        waiting, release = threading.Event(), threading.Event()
        errors = []
        replace = Path.replace
        def delayed(source, destination):
            if source.name.startswith('campaign.json.') and Path(destination).name == 'campaign.json':
                waiting.set()
                if not release.wait(10):
                    raise AssertionError('Test did not release writer')
            return replace(source, destination)
        def writer():
            try:
                write_reports(self.root, self.data)
            except BaseException as exc:
                errors.append(exc)
        with patch.object(Path, 'replace', delayed):
            thread = threading.Thread(target=writer)
            thread.start()
            try:
                self.assertTrue(waiting.wait(10))
                with self.assertRaisesRegex(RuntimeError, 'busy'):
                    rebuild(self.root, runtime_root=self.runtime)
            finally:
                release.set()
                thread.join(15)
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors, errors)
        self.assertEqual(json.loads((self.root/'campaign.json').read_text())['state'], 'RUNNING')

    def test_writer_lock_is_cross_process(self):
        code = '''
import sys
from cycle_storage import report_writer_lock
with report_writer_lock(sys.argv[1]):
    print('READY', flush=True)
    sys.stdin.readline()
'''
        proc = subprocess.Popen([sys.executable, '-c', code, str(self.root)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), 'READY')
            with self.assertRaisesRegex(RuntimeError, 'busy'):
                rebuild(self.root)
        finally:
            proc.communicate('\n', timeout=15)
        self.assertEqual(proc.returncode, 0)

    def test_pid_token_mismatch_is_not_live_owner(self):
        from cycle_storage import owner_alive, writer_identity
        identity = writer_identity()
        self.assertTrue(owner_alive(identity))
        identity['process_token'] = 'different-start-token'
        self.assertFalse(owner_alive(identity))

    def test_foreign_running_owner_is_not_assumed_dead(self):
        from cycle_storage import writer_identity
        self.data.update(state='RUNNING', writer_owner={**writer_identity(), 'host': 'another-controller.invalid'})
        write_reports(self.root, self.data)
        before = (self.root/'campaign.json').read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'another controller'):
            rebuild(self.root, runtime_root=self.runtime)
        self.assertEqual((self.root/'campaign.json').read_bytes(), before)

    def test_malformed_completion_flags_cannot_create_valid_cycles(self):
        record = copy.deepcopy(self.data['nodes'][0]['loops'][0])
        record['post_complete'] = 'false'
        write_json(self.root/'tray1_n1/loop0001/report.json', record)
        result = rebuild(self.root)
        self.assertEqual(result['nodes'][0]['completed'], 1)
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertEqual(status(result)['health'], 'FAIL')
