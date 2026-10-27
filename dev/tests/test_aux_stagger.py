"""Aux-cycle staggering: AC cycles must never hit two nodes at the same instant."""
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import test_cycle as fixtures
from test_cycle import target
from vera_cycle.core.cycle_core import digest, parse_policy
from vera_cycle.engine.cycle_engine import AuxCycleCancelled, AuxCycleGate, NodeSession
from vera_cycle import paths

AUX = '/usr/bin/stbypowerctrl.sh aux_cycle'


class GateUnitTests(unittest.TestCase):
    def test_zero_interval_never_waits(self):
        gate = AuxCycleGate(0)
        start = time.monotonic()
        for _ in range(5):
            gate.wait()
        self.assertLess(time.monotonic() - start, 0.2)

    def test_interval_is_measured_between_consecutive_releases(self):
        gate = AuxCycleGate(0.25)
        stamps = []

        def worker():
            gate.wait()
            stamps.append(time.monotonic())

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        stamps.sort()
        self.assertEqual(len(stamps), 3)
        for earlier, later in zip(stamps, stamps[1:]):
            self.assertGreaterEqual(later - earlier, 0.20)

    def test_cancelled_gate_raises_before_recording_a_release(self):
        gate = AuxCycleGate(5)
        gate.wait()
        with self.assertRaises(AuxCycleCancelled):
            gate.wait(cancelled=lambda: True)
        self.assertLess(gate.interval, 6)  # interval untouched by the cancel


class StaggeredCampaignTests(unittest.TestCase):
    setUp = fixtures.EngineTests.setUp
    tearDown = fixtures.EngineTests.tearDown

    def make_session(self, node, gate, stop=None):
        options = SimpleNamespace(**{**vars(self.options), 'cycle_mode': 'aux_cycle', 'channel': 'outband'})
        session = NodeSession(target(node=node, offset=len(node)), self.fake, self.root, 'test', b'script',
                              digest(b'script'), options,
                              parse_policy(options.issue_policy.read_text()),
                              aux_gate=gate, stop_requested=stop)
        session.precheck()
        session.start()
        return session

    def test_aux_commands_across_nodes_are_spaced(self):
        gate = AuxCycleGate(0.3)
        sessions = [self.make_session(f"n{i}", gate) for i in range(3)]
        stamps = []
        self.fake.on_action = lambda: stamps.append(time.monotonic())
        threads = [threading.Thread(target=lambda s=s: s.one_loop(1)) for s in sessions]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(stamps), 3)
        stamps.sort()
        for earlier, later in zip(stamps, stamps[1:]):
            self.assertGreaterEqual(later - earlier, 0.25, 'aux cycles reached two nodes too close together')

    def test_gate_only_applies_to_aux_cycle(self):
        for mode in ('power_cycle', 'reboot'):
            with self.subTest(mode=mode):
                gate = AuxCycleGate(30)
                options = SimpleNamespace(**{**vars(self.options), 'cycle_mode': mode, 'channel': 'outband'})
                session = NodeSession(target(), self.fake, self.root, 'test', b'script', digest(b'script'),
                                      options, parse_policy(options.issue_policy.read_text()), aux_gate=gate)
                session.precheck()
                session.start()
                start = time.monotonic()
                session.one_loop(1)
                self.assertLess(time.monotonic() - start, 5, f'{mode} must not be staggered')

    def test_operator_stop_drops_the_pending_aux_command(self):
        gate = AuxCycleGate(300)
        gate.wait()  # another node just went; the next release is far away
        sent = []
        self.fake.on_action = lambda: sent.append(1)
        session = self.make_session("n9", gate, stop=lambda: True)
        record = session.one_loop(1)

        self.assertEqual(sent, [], 'no command may reach the node after a stop')
        self.assertFalse(session.node['active'])
        self.assertIn('STOP_REQUESTED', {i['code'] for i in record['issues']})
        self.assertFalse(record['valid_cycle'])
        self.assertNotIn('cycle_command', record['commands'])

    def test_no_gate_leaves_aux_cycle_unchanged(self):
        options = SimpleNamespace(**{**vars(self.options), 'cycle_mode': 'aux_cycle'})
        session = NodeSession(target(), self.fake, self.root, 'test', b'script', digest(b'script'),
                              options, parse_policy(options.issue_policy.read_text()))
        session.precheck()
        session.start()
        start = time.monotonic()
        session.one_loop(1)
        self.assertLess(time.monotonic() - start, 5)


if __name__ == '__main__':
    unittest.main()
