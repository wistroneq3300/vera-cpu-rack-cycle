"""Offline regressions for Redfish EventLog/SEL collection. No network."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cycle_core import (Target, digest, parse_policy, redfish_delta, redfish_entries,
                        redfish_verdict)
from cycle_engine import NodeSession
from cycle_transport import Command

import test_cycle as base


def entry(i, sev, msg):
    return {"Id": str(i), "Severity": sev, "Created": "2000-01-03T04:44:02Z", "Message": msg}


class ParseTests(unittest.TestCase):
    def test_entries_normalised(self):
        parsed = redfish_entries({"Members": [entry(1, "OK", "BMC Boot"),
                                              {"Id": 2, "Severity": "Critical", "Message": "x"}]})
        self.assertEqual([e["id"] for e in parsed], ["1", "2"])
        self.assertEqual(parsed[1]["severity_key"], "critical")

    def test_missing_or_bad_payload_is_empty(self):
        for payload in (None, {}, {"Members": "x"}, 3, {"Members": [1, 2]}):
            with self.subTest(payload=payload):
                self.assertEqual(redfish_entries(payload), [])


class VerdictTests(unittest.TestCase):
    def test_worst_severity_wins(self):
        cases = [
            ([], "PASS"),
            ([entry(1, "OK", "a")], "PASS"),
            ([entry(1, "OK", "a"), entry(2, "Warning", "b")], "WARN"),
            ([entry(1, "Warning", "a"), entry(2, "Critical", "b")], "FAIL"),
            ([entry(1, "OK", "a"), entry(2, "Critical", "b")], "FAIL"),
        ]
        for entries, expected in cases:
            with self.subTest(expected=expected):
                verdict, counts = redfish_verdict(redfish_entries({"Members": entries}))
                self.assertEqual(verdict, expected)
                self.assertEqual(sum(counts.values()), len(entries))

    def test_counts_by_severity(self):
        verdict, counts = redfish_verdict(redfish_entries({"Members": [
            entry(1, "Critical", "a"), entry(2, "Warning", "b"),
            entry(3, "OK", "c"), entry(4, "OK", "d"), entry(5, "Vendor", "e")]}))
        self.assertEqual(verdict, "FAIL")
        self.assertEqual(counts, {"Critical": 1, "Warning": 1, "OK": 2, "Other": 1})


class DeltaTests(unittest.TestCase):
    def test_new_entries_by_content_not_time(self):
        old = redfish_entries({"Members": [entry(1, "OK", "boot"), entry(2, "OK", "clear")]})
        new = redfish_entries({"Members": [entry(1, "OK", "boot"), entry(2, "OK", "clear"),
                                           entry(3, "Critical", "cpl0 err")]})
        result = redfish_delta(old, new)
        self.assertEqual([e["id"] for e in result], ["3"])

    def test_reused_id_new_message_is_reported(self):
        old = redfish_entries({"Members": [entry(1, "OK", "first")]})
        new = redfish_entries({"Members": [entry(1, "Critical", "different")]})
        self.assertEqual(len(redfish_delta(old, new)), 1)


class SessionRedfishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.options = SimpleNamespace(project='neutrino', cycle_mode='power_cycle', channel='inband',
                                       boot_timeout=.03, poll_interval=.001, loops=2, hours=0, cycle=True,
                                       config_script=base.BASE/'neutrino_config.sh',
                                       issue_policy=base.BASE/'issue_policy.md',
                                       output=self.root/'output', sensor_retry_delay=0)
        self.fake = base.FakeTransport({}, self.root/'ssh')
        self.session = NodeSession(base.target(), self.fake, self.root, 'test', b'script', digest(b'script'),
                                   self.options, parse_policy(self.options.issue_policy.read_text()))

    def tearDown(self):
        self.temp.cleanup()

    def test_merged_bmc_without_sel_service(self):
        # 145-style: EventLog only, no SEL service -> SEL marked NOT PRESENT, PASS.
        self.session.precheck()
        record = self.session.node['pre']
        self.assertEqual(record['redfish_system_id'], 'System_0')
        self.assertFalse(record['redfish_sel_meta']['present'])
        self.assertTrue(record['eventlog_meta']['present'])
        self.assertEqual(record['eventlog_meta']['verdict'], 'PASS')  # single OK entry
        self.assertEqual(record['check_summary'].get('eventlog'), 'PASS')

    def test_split_bmc_with_sel_service(self):
        self.fake.redfish_sel_present = True
        self.session.precheck()
        record = self.session.node['pre']
        self.assertTrue(record['redfish_sel_meta']['present'])
        self.assertEqual(record['redfish_sel_meta']['status'], 'COLLECTED')

    def test_critical_entry_fails_eventlog_check(self):
        self.fake.redfish_eventlog = [entry(1, "OK", "boot"), entry(2, "Critical", "CPLD_0 error")]
        self.session.precheck()
        record = self.session.node['pre']
        self.assertEqual(record['eventlog_meta']['verdict'], 'FAIL')
        self.assertEqual(record['check_summary'].get('eventlog'), 'FAIL')

    def test_redfish_unavailable_is_a_failure_not_a_crash(self):
        self.fake.redfish_fail = True
        self.session.precheck()
        record = self.session.node['pre']
        self.assertIn('REDFISH_UNAVAILABLE', [i['code'] for i in record['issues']])
        self.assertFalse(record.get('eventlog_meta'))
        self.assertFalse(self.session.node['blocked'])

    def test_pre_clears_redfish_logs(self):
        self.session.precheck()
        clears = [path for _, role, path in self.fake.calls if role == 'redfish-clear']
        self.assertTrue(any(path.endswith('/EventLog/Actions/LogService.ClearLog') for path in clears),
                        f"no EventLog clear in {clears}")

    def test_loop_delta_reports_new_entries(self):
        self.session.precheck()
        self.session.start()
        original = self.fake.redfish_get
        state = {"eventlog_calls": 0}
        def get(t, path, token, timeout=30):
            if path.endswith('/EventLog/Entries'):
                state["eventlog_calls"] += 1
                # Before-cycle snapshot sees the clean baseline; POST sees a new fault.
                if state["eventlog_calls"] == 1:
                    return Command(0, json.dumps({"Members": [
                        entry(1, "OK", "xyz.openbmc_project.Logging.Cleared")]}))
                return Command(0, json.dumps({"Members": [
                    entry(1, "OK", "xyz.openbmc_project.Logging.Cleared"),
                    entry(2, "Critical", "New fault after cycle")]}))
            return original(t, path, token, timeout)
        self.fake.redfish_get = get
        record = self.session.one_loop(1)
        delta = record['eventlog_meta']['delta']
        self.assertEqual(delta['status'], 'COMPARED')
        self.assertEqual(delta['new_count'], 1)
        self.assertEqual(delta['new_entries'][0]['message'], 'New fault after cycle')


if __name__ == '__main__':
    unittest.main()
