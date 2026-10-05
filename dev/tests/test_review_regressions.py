"""Review acceptance tests: production parsing, engine and real upload contract."""
import copy
import io
import json
import runpy
import unittest
from pathlib import Path
from unittest.mock import patch

from cycle_core import (aggregate_issues, classify_against_pre, dmesg_issues, health,
                        issue_baseline, parse_pci, parse_sensors, pci_issues, sensor_issues)
from cycle_report import record_html
from cycle_transport import Command, Transport
from neutrino_cycle import show_result
import test_cycle


def apei(severity, bdf='0000:01:00.0', source=8194, token=1):
    return (f'[ 1.0] {{{token}}}[Hardware Error]: Hardware error from APEI Generic Hardware Error Source: {source}\n'
            f'[ 1.1] {{{token}}}[Hardware Error]: event severity: {severity}\n'
            f'[ 1.2] {{{token}}}[Hardware Error]: device: {bdf}\n')


class EventTests(unittest.TestCase):
    def test_native_enum_and_section_severity(self):
        for severity, expected in [('info', 'PASS'), ('corrected', 'WARN'), ('recoverable', 'WARN'),
                                   ('fatal', 'FAIL'), ('uncorrected', 'FAIL'), ('unknown', 'FAIL')]:
            with self.subTest(severity=severity):
                items = dmesg_issues(apei(severity))
                self.assertEqual(health(items), expected)
                if items:
                    self.assertEqual(items[0]['native_severity'], severity)
        items = dmesg_issues(apei('info') + '{1}[Hardware Error]: Error 0, type: recoverable\n')
        self.assertEqual(health(items), 'WARN')

    def test_adjacent_and_interleaved_events(self):
        for first in ('info', 'corrected'):
            items = dmesg_issues(apei(first) + apei('fatal', source=8195, token=2))
            self.assertEqual(items[-1]['source'], '8195')
            self.assertEqual(items[-1]['native_severity'], 'fatal')
            self.assertEqual(len(items), 1 if first == 'info' else 2)
        a, b = apei('corrected').splitlines(), apei('fatal', token=2).splitlines()
        items = dmesg_issues('\n'.join([a[0], b[0], a[1], 'normal initialization', b[1], a[2], b[2]]))
        self.assertEqual([i['severity'] for i in items], ['WARN', 'FAIL'])
        self.assertEqual(items[0]['raw_lines'], [1, 3, 6])
        self.assertEqual(len(dmesg_issues(apei('fatal') + apei('fatal'))), 2)
        self.assertEqual(health(dmesg_issues(a[0])), 'FAIL')
        self.assertEqual(health(dmesg_issues('[Hardware Error]: event severity: unknown')), 'FAIL')

    def test_native_families_and_normal_initialization(self):
        for line, family in [('PCIe Bus Error: severity=Uncorrectable (Fatal)', 'PCIE'),
                             ('EDAC MC0: 1 UE on DIMM1', 'EDAC'),
                             ('SError Interrupt on CPU0', 'ARM'),
                             ('I/O error, dev nvme0n1, sector 12', 'NVME'),
                             ('mlx5_core 0000:01:00.0: fatal error', 'NIC'),
                             ('Kernel panic - not syncing', 'KERNEL'),
                             ('NVRM: Xid (PCI:0000:01:00): 79, GPU has fallen off the bus', 'GPU')]:
            with self.subTest(line=line):
                self.assertEqual(dmesg_issues(line)[0]['family'], family)
        self.assertFalse(dmesg_issues('AER: enabled error reporting\nnvme nvme0: 32 queues\nEDAC initialized\n0 errors'))

    def test_real_parser_classification_console_and_aggregation(self):
        pre = dmesg_issues(apei('corrected'))
        for text, expected in [(apei('fatal'), 'WORSENED'), (apei('recoverable'), 'WORSENED'), (apei('corrected')*3, 'WORSENED'),
                               (apei('corrected', bdf='0000:02:00.0'), 'NEW'),
                               ('Kernel panic - not syncing', 'NEW'), (apei('corrected'), 'KNOWN')]:
            items = classify_against_pre(dmesg_issues(text), issue_baseline(pre))
            self.assertTrue(all(i['classification'] == expected for i in items))
        post = classify_against_pre(dmesg_issues('Kernel panic - not syncing'), issue_baseline(pre))
        record = dict(phase='LOOP 1', status='FAIL', issues=post)
        output = []
        node = dict(key='n1', pre=dict(phase='PRE', issues=pre), loops=[record], blocked=[])
        show_result(output.append, node, record)
        self.assertIn('panic', '\n'.join(output))
        groups = aggregate_issues(dict(nodes=[node]))
        self.assertEqual(len(groups), 2)
        self.assertEqual(health(groups), 'FAIL')

    def test_sensor_name_validation_precedes_shortcuts(self):
        for line in ['CPU0_\ufffdTemp | 30 | degrees C | ok', 'NVMe_\ufffdSTS | 0x1 | discrete | 0x0100',
                     'PrMo0CP1CorUti\ufffd | na | percent | na', 'otherCorUti | na | percent | na']:
            self.assertEqual(health(sensor_issues(parse_sensors(line))), 'FAIL')
        self.assertFalse(sensor_issues(parse_sensors('PrMo0CP1CorUti11 | na | percent | na')))

    def test_pci_description_is_evidence_not_identity(self):
        a = parse_pci('0000:01:00.0 Device A [1234:5678]')
        b = parse_pci('0000:01:00.0 Updated name [1234:5678]')
        self.assertFalse(pci_issues(a, b))

    def test_real_sensor_fixtures_are_part_of_discovery(self):
        paths = sorted((Path(__file__).parents[1]/'fixtures/real-hardware').glob('*_sensor_list.txt'))
        self.assertEqual(len(paths), 3)
        for path in paths:
            rows = parse_sensors(path.read_text(encoding='utf-8'))
            self.assertEqual(len(rows), 240)
            findings = sensor_issues(rows)
            self.assertEqual(health(findings), 'WARN')
            self.assertEqual(sum(i['code'] == 'SENSOR_DUPLICATE' for i in findings), 4)


class EngineReviewTests(unittest.TestCase):
    setUp = test_cycle.EngineTests.setUp
    tearDown = test_cycle.EngineTests.tearDown
    ready = test_cycle.EngineTests.ready
    run_campaign = test_cycle.EngineTests.run_campaign

    def hardware_calls(self):
        return [cmd for _, _, cmd in self.fake.calls if ' bash ' in cmd or cmd.startswith('bash ')]

    def test_all_upload_validation_failures_block_execution(self):
        original = self.fake.ssh
        for kind in ('upload', 'partial', 'mismatch', 'empty', 'sha_exit', 'unsafe'):
            with self.subTest(kind=kind):
                self.session.upload_attempted = False
                self.session.node['blocked'] = []
                self.fake.calls.clear()
                def upload(*args):
                    if kind in {'upload', 'partial'}:
                        if kind == 'partial':
                            self.fake.uploaded[self.session.target.key] = b'scri'
                        raise OSError('partial transfer' if kind == 'partial' else 'upload failed')
                    self.fake.uploaded[self.session.target.key] = b'script'
                def ssh(t, role, cmd, timeout=60, sudo=False):
                    if cmd.startswith('sha256sum'):
                        if kind == 'empty': return Command(0, '')
                        if kind == 'sha_exit': return Command(1, 'failed')
                        if kind == 'mismatch': return Command(0, '0'*64 + ' file')
                    if cmd.startswith('test -f') and kind == 'unsafe': return Command(1, 'unsafe')
                    return original(t, role, cmd, timeout, sudo)
                with patch.object(self.fake, 'upload', side_effect=upload), patch.object(self.fake, 'ssh', side_effect=ssh):
                    self.session.precheck()
                self.assertFalse(self.hardware_calls())
                self.assertTrue(self.session.node['blocked'])

    def test_single_upload_reuse_and_post_corruption_gate(self):
        with patch.object(self.fake, 'upload', wraps=self.fake.upload) as upload:
            self.ready()
            self.session.one_loop(1)
            self.assertEqual(upload.call_count, 1)
            self.assertEqual(len(self.hardware_calls()), 2)
            self.fake.uploaded[self.session.target.key] = b'corrupt'
            record = self.session.one_loop(2)
            self.assertEqual(upload.call_count, 1)
            self.assertEqual(len(self.hardware_calls()), 2)
            self.assertFalse(self.session.node['active'])
            self.assertIn('SCRIPT_VALIDATION_FAILED', [i['code'] for i in record['issues']])

    def test_pre_immutable_and_start_evidence_retained(self):
        # Clean-start clearing moved into PRE; START only re-verifies identity.
        # PRE now wipes the ring buffer with `dmesg -C` (read-free), so a panic
        # present before the clear is deliberately discarded and never enters the
        # PRE baseline. The PRE record stays immutable across START.
        original_dmesg = self.fake.ssh
        with patch.object(self.fake, 'ssh', side_effect=lambda t, r, c, timeout=60, sudo=False:
                          Command(0, 'Kernel panic before start') if c == 'dmesg -C' else original_dmesg(t, r, c, timeout, sudo)):
            self.session.precheck()
        self.assertFalse(any('panic' in i.get('detail', '') for i in self.session.node['pre']['issues']))
        frozen = copy.deepcopy(self.session.node['pre'])
        before = (self.root/'tray1_n1/pre_report.json').read_bytes()
        self.session.start()
        self.assertEqual(self.session.node['pre'], frozen)
        self.assertEqual((self.root/'tray1_n1/pre_report.json').read_bytes(), before)
        self.assertTrue(self.session.node['start']['identities'])

    def test_ring_buffer_check_tail_and_next_action_evidence(self):
        self.ready()
        ring = []
        original = self.fake.ssh
        def ssh(t, role, cmd, timeout=60, sudo=False):
            if cmd in {'dmesg', 'dmesg -c'}:
                text = '\n'.join(ring)
                if cmd == 'dmesg -c': ring.clear()
                return Command(0, text)
            if cmd.startswith('MEMORY_MIN_RATIO='):
                ring.append('[ 10.0] AER: Uncorrected error at 0000:01:00.0')
            if cmd == 'ipmitool power cycle': ring.clear()
            return original(t, role, cmd, timeout, sudo)
        with patch.object(self.fake, 'ssh', side_effect=ssh):
            first = self.session.one_loop(1)
            ring.append('[ 11.0] Kernel panic between loops')
            second = self.session.one_loop(2)
        for record, fragment in [(first, 'AER'), (second, 'panic')]:
            event = next(i for i in record['issues'] if fragment in i['detail'])
            self.assertIn(fragment, (self.root/event['evidence']).read_text())
        self.assertIn('dmesg_clear', first['issues'][-1]['phase'])
        self.assertEqual(first['dmesg_delta']['FAIL'], 1)

    def test_read_clear_dedup_keeps_distinct_bdfs_and_raw(self):
        self.ready()
        record = self.session.node['pre'].copy()
        record.update(issues=[], commands={}, evidence=[])
        a, b = apei('fatal'), apei('fatal', bdf='0000:02:00.0', token=2)
        with patch.object(self.fake, 'ssh', side_effect=[Command(0, a), Command(0, a+b)]):
            self.session.collect_dmesg(record, 'first')
            self.session.collect_dmesg(record, 'clear', clear=True)
        self.assertEqual(len(record['issues']), 2)
        self.assertTrue(record['issues'][1]['evidence'].endswith('pre_clear.txt'))
        self.assertIn('0000:02:00.0', (self.root/record['issues'][1]['evidence']).read_text())

    def test_extra_boot_stops_node(self):
        self.ready()
        original = self.fake.ssh
        def ssh(t, role, cmd, timeout=60, sudo=False):
            result = original(t, role, cmd, timeout, sudo)
            if cmd.startswith('MEMORY_MIN_RATIO='):
                self.fake.boots[t.key] += 1
            return result
        with patch.object(self.fake, 'ssh', side_effect=ssh):
            record = self.session.one_loop(1)
        self.assertFalse(self.session.node['active'])
        self.assertFalse(record['post_complete'])
        self.assertEqual(self.session.node['valid_cycles'], 0)

    def test_rejected_action_is_not_valid_cycle_and_sel_delta_is_not_empty_sel(self):
        self.ready()
        self.fake.fail_command = True
        record = self.session.one_loop(1)
        self.assertEqual(self.session.node['attempts'], 1)
        self.assertEqual(self.session.node['completed'], 1)
        self.assertEqual(self.session.node['valid_cycles'], 0)
        html = record_html(record, 0)
        self.assertIn('0 new events', html)
        self.assertNotIn('BMC returned no SEL records', html)

    def test_preparation_time_does_not_consume_execution_budget(self):
        self.options.loops = 1
        self.options.hours = 1/3600
        clock = [0.0]
        start = test_cycle.NodeSession.start
        def slow_start(session):
            start(session)
            clock[0] += 2
        with patch('neutrino_cycle.time.monotonic', side_effect=lambda: clock[0]), patch.object(test_cycle.NodeSession, 'start', slow_start):
            self.run_campaign()
        path = next(self.options.output.glob('*/campaign.json'))
        data = json.loads(path.read_text())
        self.assertEqual(data['nodes'][0]['attempts'], 1)
        self.assertEqual(data['nodes'][0]['valid_cycles'], 1)

    def test_collection_failure_continues_checks_and_keeps_historical_fail(self):
        self.ready()
        ssh = self.fake.ssh
        def unavailable(t, role, cmd, timeout=60, sudo=False):
            if cmd == 'lsblk': raise ConnectionError('collection interrupted')
            return ssh(t, role, cmd, timeout, sudo)
        with patch.object(self.fake, 'ssh', side_effect=unavailable):
            record = self.session.one_loop(1)
        self.assertEqual(record['status'], 'FAIL')
        self.assertTrue(record['post_complete'])
        self.assertTrue(self.session.node['active'])
        self.assertIn('dmesg_clear', record['commands'])
        self.fake.hardware_failure = False
        self.session.one_loop(2)
        self.assertEqual(health(aggregate_issues(dict(nodes=[self.session.node]))), 'FAIL')

    def test_boot_change_while_awaiting_approval_prevents_log_clearing(self):
        self.session.precheck()
        before = copy.deepcopy(self.session.node['pre'])
        self.fake.boots[self.session.target.key] = 99
        self.fake.calls.clear()
        with self.assertRaisesRegex(test_cycle.IdentityUnsafe, 'awaiting PRE approval'):
            self.session.start()
        self.session.cleanup_remote()
        self.assertFalse(any(cmd in {'dmesg -c', 'ipmitool sel clear', 'sel clear'} or cmd.startswith('rm ') for _, _, cmd in self.fake.calls))
        self.assertEqual(self.session.node['pre'], before)

    def test_missing_post_script_is_never_reuploaded(self):
        self.ready()
        ssh = self.fake.ssh
        before = len(self.hardware_calls())
        with patch.object(self.fake, 'upload', side_effect=AssertionError('must not upload twice')):
            with patch.object(self.fake, 'ssh', side_effect=lambda t, r, c, timeout=60, sudo=False:
                              Command(1, 'missing file') if c.startswith('test -f') else ssh(t, r, c, timeout, sudo)):
                self.session.one_loop(1)
        self.assertEqual(len(self.hardware_calls()), before)
        self.assertFalse(self.session.node['active'])


class LegacyTests(unittest.TestCase):
    def test_legacy_stops_before_network_or_credentials(self):
        with patch('subprocess.run', side_effect=AssertionError('No live process allowed')):
            with self.assertRaisesRegex(SystemExit, 'Disabled legacy live utility'):
                runpy.run_path(str(Path(__file__).parents[1]/'dryrun_sim.py'), run_name='__main__')


class UploadContractTests(unittest.TestCase):
    def test_real_transport_retains_exclusive_create(self):
        files = {}
        class Stream(io.BytesIO):
            def close(self):
                files['script'] = self.getvalue()
                super().close()
        class SFTP:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def get_channel(self): return self
            def settimeout(self, value): pass
            def file(self, path, mode):
                self.mode = mode
                if mode != 'wx': raise AssertionError('Exclusive create required')
                if path in files: raise FileExistsError(path)
                return Stream()
            def chmod(self, path, mode): self.permissions = mode
        class Client:
            def open_sftp(self): return sftp
            def close(self): pass
        sftp = SFTP()
        transport = Transport({}, '.')
        with patch.object(transport, '_connect', return_value=Client()):
            transport.upload(None, b'verified', 'script')
            self.assertEqual(files['script'], b'verified')
            self.assertEqual(sftp.permissions, 0o700)
            with self.assertRaises(FileExistsError): transport.upload(None, b'other', 'script')
            self.assertEqual(files['script'], b'verified')
