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

# Keep the campaign journal out of the real /srv/cycletmp during tests.
os.environ.setdefault('VERA_CAMPAIGN_TMP', tempfile.mkdtemp(prefix='vera-campaign-tmp-'))

from vera_cycle.core.cycle_core import issue, now, write_json
from vera_cycle.engine.cycle_engine import new_record
from vera_cycle.reporting.cycle_report import journal_path, rebuild, render_html, status, write_reports
from vera_cycle.engine.cycle_runtime import RunRegistry
from vera_cycle.cli import main
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
        self.assertEqual(json.loads(journal_path(self.root).read_text())['nodes'][0]['completed'], 1)

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
        before = journal_path(self.root).read_bytes()
        with patch.dict(os.environ, {'VERA_RUNTIME_DIR': str(self.runtime)}), contextlib.redirect_stderr(io.StringIO()):
            code = main(['--report', str(self.root)])
        self.assertEqual(code, 2)
        self.assertEqual(journal_path(self.root).read_bytes(), before)
        self.assertEqual(json.loads((registry.path/'owner.json').read_text())['state'], 'RUNNING')

    def test_cli_rebuild_accepts_an_explicit_journal_override(self):
        # A journal copied out of its Run-ID directory must be reachable through
        # --journal; without the flag the CLI used to crash on an unknown option.
        self.save()
        (self.root/'tray1_n1/loop0001/report.json').unlink()
        moved = self.root/'moved.json'
        moved.write_bytes(journal_path(self.root).read_bytes())
        journal_path(self.root).unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(['--report', str(self.root), '--journal', str(moved)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(journal_path(self.root).read_text())['state'], 'INCOMPLETE')

    def test_journal_recovers_after_bundle_directory_rename(self):
        # The journal is keyed by the bundle directory name. After a rename the
        # Run ID in the bundle text still finds it, so an offline copy rebuilds
        # instead of failing with "journal not found".
        self.save()
        (self.root/'tray1_n1/loop0001/report.json').unlink()
        (self.root/'cycle_summary.txt').write_text(f"Run ID: {self.data['run_id']}\n", encoding='utf-8')
        moved_journal = self.root.parent/'moved-journal.json'
        moved_journal.write_bytes(journal_path(self.root).read_bytes())
        journal_path(self.root).unlink()
        renamed = self.root.parent/'renamed-bundle'
        self.root.rename(renamed)
        previous = os.environ.get('VERA_CAMPAIGN_TMP')
        try:
            # Point the journal root at a directory whose child name no longer
            # matches the bundle; only the run_id scan can find it.
            scan_root = self.root.parent/'scan-root'
            (scan_root/self.data['run_id']).mkdir(parents=True)
            (scan_root/self.data['run_id']/'campaign.json').write_bytes(moved_journal.read_bytes())
            os.environ['VERA_CAMPAIGN_TMP'] = str(scan_root)
            result = rebuild(renamed, runtime_root=self.runtime)
        finally:
            renamed.rename(self.root)
            if previous is None:
                os.environ.pop('VERA_CAMPAIGN_TMP', None)
            else:
                os.environ['VERA_CAMPAIGN_TMP'] = previous
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertEqual(result['nodes'][0]['completed'], 1)

    def test_missing_journal_failure_names_every_candidate(self):
        from vera_cycle.reporting.cycle_report import journal_candidates, read_journal
        absent = self.root.parent/'no-such-bundle'
        absent.mkdir()
        with self.assertRaises(FileNotFoundError) as caught:
            read_journal(absent)
        message = str(caught.exception)
        for candidate in journal_candidates(absent):
            self.assertIn(str(candidate), message)
        self.assertIn('--journal', message)

    def test_dead_real_owner_allows_recovery(self):
        code = '''
import json, sys
from pathlib import Path
from vera_cycle.engine.cycle_runtime import RunRegistry
from vera_cycle.reporting.cycle_report import journal_path
from vera_cycle.core.cycle_storage import writer_identity
from vera_cycle.core.cycle_core import write_json
root=Path(sys.argv[1]); path=journal_path(root)
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
        self.assertEqual(json.loads(journal_path(self.root).read_text())['state'], 'RUNNING')

    def test_writer_lock_is_cross_process(self):
        code = '''
import sys
from vera_cycle.core.cycle_storage import report_writer_lock
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
        from vera_cycle.core.cycle_storage import owner_alive, writer_identity
        identity = writer_identity()
        self.assertTrue(owner_alive(identity))
        identity['process_token'] = 'different-start-token'
        self.assertFalse(owner_alive(identity))

    def test_foreign_running_owner_is_not_assumed_dead(self):
        from vera_cycle.core.cycle_storage import writer_identity
        self.data.update(state='RUNNING', writer_owner={**writer_identity(), 'host': 'another-controller.invalid'})
        write_reports(self.root, self.data)
        before = journal_path(self.root).read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'another controller'):
            rebuild(self.root, runtime_root=self.runtime)
        self.assertEqual(journal_path(self.root).read_bytes(), before)

    def test_malformed_completion_flags_cannot_create_valid_cycles(self):
        record = copy.deepcopy(self.data['nodes'][0]['loops'][0])
        record['post_complete'] = 'false'
        write_json(self.root/'tray1_n1/loop0001/report.json', record)
        result = rebuild(self.root)
        self.assertEqual(result['nodes'][0]['completed'], 1)
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertEqual(status(result)['health'], 'FAIL')


class DegradedOutputTests(unittest.TestCase):
    """Journal and report are written independently; neither breaks the other.

    Regression: both were written in one try block, so a full disk outside the
    bundle (where the journal lives) also cost the operator the HTML -- the one
    artefact readable without the tool.
    """

    setUp = RecoveryTests.setUp
    save = RecoveryTests.save

    def test_journal_failure_still_renders_report(self):
        from vera_cycle.reporting.cycle_report import ReportDegraded
        real = write_json
        def boom(path, payload):
            if 'campaign.json' in str(path):
                raise OSError('No space left on device')
            return real(path, payload)
        with patch('vera_cycle.reporting.cycle_report.write_json', boom):
            with self.assertRaises(ReportDegraded) as caught:
                write_reports(self.root, self.data)
        self.assertEqual(caught.exception.persistence['state'], 'FAILED')
        self.assertEqual(caught.exception.report['state'], 'READY')
        self.assertTrue((self.root/'CYCLE_REVIEW_REPORT.html').is_file())
        # The journal from setUp is left untouched, not deleted or half-written.
        self.assertEqual(read_journal_text(self.root)['state'], 'COMPLETE')

    def test_render_failure_keeps_journal_and_marks_report(self):
        from vera_cycle.reporting.cycle_report import ReportDegraded
        with patch('vera_cycle.reporting.cycle_report.render_html', side_effect=ValueError('bad template')):
            with self.assertRaises(ReportDegraded) as caught:
                write_reports(self.root, self.data)
        self.assertEqual(caught.exception.report['state'], 'FAILED')
        self.assertEqual(caught.exception.persistence['state'], 'OK')
        # The verdict of record survives a broken template.
        self.assertTrue(journal_path(self.root).is_file())
        self.assertEqual(read_journal_text(self.root)['state'], 'COMPLETE')

    def test_node_degraded_archive_is_part_of_run_status(self):
        from vera_cycle.reporting.cycle_report import run_status
        self.data['nodes'][0].update(persistence='DEGRADED',
                                     persistence_detail='tray1_n1/loop0001/report.json: OSError')
        verdict = run_status(self.data)
        self.assertEqual(verdict['persistence']['state'], 'DEGRADED')
        self.assertIn('loop0001/report.json', verdict['persistence']['detail'])
        self.assertEqual(verdict['execution'], 'COMPLETE')
        self.assertEqual(verdict['health'], 'FAIL')

    def test_run_status_file_is_written_even_when_journal_fails(self):
        import json as jsonlib
        from vera_cycle.reporting.cycle_report import ReportDegraded
        real = write_json
        def boom(path, payload):
            if 'campaign.json' in str(path):
                raise OSError('disk full')
            return real(path, payload)
        with patch('vera_cycle.reporting.cycle_report.write_json', boom):
            with self.assertRaises(ReportDegraded):
                write_reports(self.root, self.data)
        payload = jsonlib.loads((self.root/'run_status.json').read_text())
        self.assertEqual(payload['persistence']['state'], 'FAILED')
        self.assertIn('disk full', payload['persistence']['detail'])
        self.assertIn('Persistence: FAILED', (self.root/'cycle_summary.txt').read_text())


def read_journal_text(root):
    return json.loads(journal_path(root).read_text())


class DegradedBannerTests(unittest.TestCase):
    """The banner is the only part of the verdict a reader sees without tools.

    It carries persistence failures only. The report's own state cannot be
    stated inside the report ("was this HTML written?" is unknown until after
    it is written), so that lives in run_status.json.
    """

    setUp = RecoveryTests.setUp
    save = RecoveryTests.save

    BANNER = '<div class="degraded-banner">'

    def test_healthy_campaign_has_no_banner(self):
        # Matched as an element, not as a substring: the CSS is inlined and
        # defines .degraded-banner, so a substring test passes when nothing shows.
        html = render_html(self.data)
        self.assertNotIn(self.BANNER, html)

    def test_journal_failure_shows_banner(self):
        self.data['persistence'] = dict(state='FAILED', detail='OSError: No space left on device')
        html = render_html(self.data)
        self.assertIn(self.BANNER, html)
        self.assertIn('No space left on device', html)
        # The verdict itself must not be rewritten by an output problem.
        self.assertIn('COMPLETE', html)
        self.assertIn('FAIL', html)

    def test_node_archive_failure_shows_its_own_row(self):
        self.data['nodes'][0].update(persistence='DEGRADED',
                                     persistence_detail='tray1_n1/loop0001/report.json: OSError')
        html = render_html(self.data)
        self.assertIn(self.BANNER, html)
        self.assertIn('tray1_n1/loop0001/report.json', html)

    def test_ok_node_states_do_not_trigger_it(self):
        self.data['nodes'][0]['persistence'] = 'OK'
        self.assertNotIn(self.BANNER, render_html(self.data))

    def test_banner_survives_print(self):
        # Handed over as PDF: the warning must be on paper too.
        from vera_cycle.reporting.cycle_report import ASSETS
        css = (ASSETS / 'report.css').read_text()
        self.assertNotIn('.degraded-banner{display:none', css)
        self.assertIn('.degraded-banner', css)
