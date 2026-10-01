"""R2-01/02/03/06: exercise real engine, classification and scheduler paths."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

import test_cycle as fixtures
from cycle_core import aggregate_issues, health
from cycle_transport import Command
from neutrino_cycle import campaign, show_result


INCOMPLETE = [
    Command(255, 'not sent', 'NOT_ISSUED'),
    Command(124, 'timed out', 'RESPONSE_LOST'),
    Command(2, 'syntax error', 'RETURNED'),
    Command(0, 'CHECK|CPU|actual=2\n', 'RETURNED'),
    Command(0, 'RESULT|PASS\n', 'RESPONSE_LOST'),
    Command(1, 'RESULT|PASS\n', 'RETURNED'),
    Command(0, 'RESULT|FAIL\n', 'RETURNED'),
    Command(0, 'RESULT|PASS\ntrailing output', 'RETURNED'),
    Command(0, 'RESULT|PASS\nRESULT|PASS\n', 'RETURNED'),
]


class ExecutionTests(unittest.TestCase):
    setUp = fixtures.EngineTests.setUp
    tearDown = fixtures.EngineTests.tearDown

    def replace_hardware(self, replacement, selected=None):
        original = self.fake.ssh
        def ssh(t, role, cmd, timeout=60, sudo=False):
            if cmd.startswith('MEMORY_MIN_RATIO=') and (selected is None or selected(t)):
                self.fake.calls.append((t.key, role, cmd))
                return replacement
            return original(t, role, cmd, timeout, sudo)
        return patch.object(self.fake, 'ssh', side_effect=ssh)

    def test_post_incomplete_execution_stops_before_next_action(self):
        for result in INCOMPLETE:
            with self.subTest(code=result.code, state=result.state, output=result.output):
                session = fixtures.NodeSession(fixtures.target(), self.fake, self.root, 'test', b'script',
                                               fixtures.digest(b'script'), self.options, [])
                session.precheck()
                session.start()
                with self.replace_hardware(result):
                    record = session.one_loop(1)
                    actions = session.node['attempts']
                    if session.node['active']:
                        session.one_loop(2)  # model the real scheduler, not a bypass
                self.assertEqual(session.node['attempts'], actions)
                self.assertFalse(session.node['active'])
                self.assertFalse(record.get('hardware_execution_complete', True))
                self.assertFalse(record['post_complete'])
                self.assertFalse(record.get('valid_cycle', False))
                self.assertTrue(record['script_verified'])
                self.assertIn('dmesg_clear', record['commands'])
                self.assertEqual(record['status'], 'FAIL')
                self.assertIn('HARDWARE_EXECUTION_INCOMPLETE', [i['code'] for i in record['issues']])

    def test_pre_incomplete_execution_blocks_approval(self):
        for result in INCOMPLETE[:4]:
            session = fixtures.NodeSession(fixtures.target(), self.fake, self.root, 'test', b'script',
                                           fixtures.digest(b'script'), self.options, [])
            with self.replace_hardware(result):
                session.precheck()
            self.assertTrue(session.node['blocked'])
            self.assertFalse(session.node['active'])
            self.assertTrue(session.baseline['pci'])

    def test_complete_hardware_fail_is_keep_going(self):
        self.session.precheck()
        self.session.start()
        for n in (1, 2):
            record = self.session.one_loop(n)
            self.assertTrue(record['hardware_execution_complete'])
            self.assertTrue(record['post_complete'])
            self.assertTrue(record['valid_cycle'])
            self.assertEqual(record['status'], 'FAIL')
            self.assertTrue(self.session.node['active'])

    def test_two_nodes_only_execution_failure_stops(self):
        targets = [fixtures.target(), fixtures.target('n2', offset=2)]
        self.options.loops = 2
        with self.replace_hardware(Command(124, 'timeout', 'RESPONSE_LOST'),
                                   lambda t: t.node == 'n1' and self.fake.boots.get(t.key, 0) > 0):
            with contextlib.redirect_stdout(io.StringIO()):
                code = campaign(self.options, targets, {}, confirm=lambda _: 'yes',
                                transport_factory=lambda *_: self.fake, runtime_root=self.root/'runtime')
        data = json.loads(next(self.options.output.glob('*/campaign.json')).read_text())
        first, second = data['nodes']
        self.assertEqual(code, 1)
        self.assertEqual(first['attempts'], 1)
        self.assertEqual(first['completed'], 0)
        self.assertEqual(second['attempts'], 2)
        self.assertEqual(second['completed'], 2)
        self.assertEqual(second['valid_cycles'], 2)

    def test_rejected_or_unissued_extra_boot_is_not_adopted(self):
        for response in (Command(1, 'rejected'), Command(255, 'not issued', 'NOT_ISSUED')):
            session = fixtures.NodeSession(fixtures.target(), self.fake, self.root, 'test', b'script',
                                           fixtures.digest(b'script'), self.options, [])
            session.precheck()
            session.start()
            before = session.expected_boot
            def action(t):
                self.fake.boots[t.key] = self.fake.boots.get(t.key, 0) + 1
                return response
            with patch.object(self.fake, 'action', side_effect=action):
                record = session.one_loop(1)
            self.assertFalse(session.node['active'])
            self.assertEqual(session.expected_boot, before)
            self.assertNotEqual(record['recovery']['post_entry_boot_id'], before)
            self.assertEqual(session.node['valid_cycles'], 0)
            self.assertIn('CYCLE_COMMAND_FAILED', [i['code'] for i in record['issues']])
            self.assertIn('UNEXPECTED_BOOT_TRANSITION', [i['code'] for i in record['issues']])

    def test_rejected_same_boot_and_lost_response_controls(self):
        self.session.precheck()
        self.session.start()
        self.fake.fail_command = True
        record = self.session.one_loop(1)
        self.assertTrue(self.session.node['active'])
        self.assertTrue(record['post_complete'])
        self.assertFalse(record['valid_cycle'])
        self.fake.fail_command = False
        self.fake.response_lost = True
        record = self.session.one_loop(2)
        self.assertTrue(record['valid_cycle'])
        self.assertEqual(record['action'][0]['state'], 'RECONCILED')
        self.assertEqual(self.session.node['attempts'], 2)

    def test_nvme_normal_and_real_timeout_full_pipeline(self):
        self.fake.hardware_failure = False
        normal = '[ 1.0] nvme nvme0: Shutdown timeout set to 10 seconds'
        original = self.fake.ssh
        text = [normal]
        def ssh(t, role, cmd, timeout=60, sudo=False):
            if cmd in {'dmesg', 'dmesg -c'}:
                return Command(0, text[0] if self.fake.boots.get(t.key, 0) >= 2 else normal)
            return original(t, role, cmd, timeout, sudo)
        with patch.object(self.fake, 'ssh', side_effect=ssh):
            self.session.precheck()
            self.session.start()
            first = self.session.one_loop(1)
            output = []
            show_result(output.append, self.session.node, first)
            self.assertEqual(first['status'], 'PASS')
            self.assertEqual(first['dmesg_delta'], {'WARN': 0, 'FAIL': 0})
            self.assertEqual(health(aggregate_issues({'nodes': [self.session.node]})), 'PASS')
            self.assertNotIn('DMESG_NVME', '\n'.join(output))
            text[0] = '[ 2.0] nvme nvme0: I/O 12 QID 1 timeout, aborting\n[ 2.1] nvme nvme0: controller is down; will reset'
            second = self.session.one_loop(2)
        self.assertEqual(second['status'], 'FAIL')
        self.assertEqual(second['dmesg_delta']['FAIL'], 2)
        output = []
        show_result(output.append, self.session.node, second)
        self.assertIn('timeout', '\n'.join(output))
        self.assertEqual(health(aggregate_issues({'nodes': [self.session.node]})), 'FAIL')
