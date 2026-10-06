"""Offline regressions for Redfish collection/verdict/evidence correctness.

Covers P1-2 (severity -> canonical issue), P1-4 (discovery failure is not
"not present"), P1-5 (malformed collection is not an empty PASS), P1-6
(pagination), P2-1 (delta requires valid+complete snapshots) and P2-2 (PRE
dmesg finding links to a real evidence file). No network access.
"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cycle_core import classify_against_pre, digest, issue_baseline, parse_policy
from cycle_engine import NodeSession
from cycle_report import status
from cycle_transport import Command

import test_cycle as base


def entry(i, sev, msg):
    return {"Id": str(i), "Severity": sev, "Created": "2000-01-03T04:44:02Z", "Message": msg}


class FakeRedfish(base.FakeTransport):
    """FakeTransport with a controllable Redfish surface.

    ``eventlog_pages`` / ``sel_pages`` are lists of page payload dicts (each may
    carry a ``Members@odata.nextLink``) or a Command to simulate a failed page.
    ``logservices`` overrides the discovery response.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.eventlog_pages = [{"Members": [entry(1, "OK", "boot")]}]
        self.sel_pages = [{"Members": []}]
        self.logservices = None
        self.systems = None
        self.clear_status = 0
        self.entries_fail_paths = {}

    def redfish_get(self, target, path, token, timeout=30):
        self.calls.append((target.key, 'redfish', path))
        if path in self.entries_fail_paths:
            return self.entries_fail_paths[path]
        path = path.split('?', 1)[0]  # pages may carry ?page=N query strings
        if path == '/redfish/v1/Systems':
            if self.systems is not None:
                return self.systems
            return Command(0, json.dumps({"Members": [{"@odata.id": "/redfish/v1/Systems/System_0"}]}))
        if path.endswith('/LogServices'):
            if self.logservices is not None:
                return self.logservices
            members = [{"@odata.id": "/redfish/v1/Systems/System_0/LogServices/EventLog"}]
            if self.redfish_sel_present:
                members.append({"@odata.id": "/redfish/v1/Systems/System_0/LogServices/SEL"})
            return Command(0, json.dumps({"Members": members}))
        if path.endswith('/EventLog/Entries'):
            return self._page(self.eventlog_pages)
        if path.endswith('/SEL/Entries'):
            return self._page(self.sel_pages)
        return Command(127, 'Unsupported fake Redfish path: ' + path)

    def _page(self, pages):
        payload = pages.pop(0) if len(pages) > 1 else pages[0]
        if isinstance(payload, Command):
            return payload
        return Command(0, json.dumps(payload))

    def redfish_clear(self, target, path, token, timeout=30):
        self.calls.append((target.key, 'redfish-clear', path))
        return Command(self.clear_status, 'OK' if self.clear_status == 0 else 'clear rejected')


class RedfishSessionCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.options = SimpleNamespace(project='neutrino', cycle_mode='power_cycle', channel='inband',
                                       boot_timeout=.03, poll_interval=.001, loops=1, hours=0, cycle=True,
                                       config_script=base.BASE/'neutrino_config.sh',
                                       issue_policy=base.BASE/'issue_policy.md',
                                       output=self.root/'output', sensor_retry_delay=0)
        self.fake = FakeRedfish({}, self.root/'ssh')
        self.session = NodeSession(base.target(), self.fake, self.root, 'test', b'script', digest(b'script'),
                                   self.options, parse_policy(self.options.issue_policy.read_text()))

    def tearDown(self):
        self.temp.cleanup()

    def collect(self, record=None):
        record = record or self.session.node['pre']
        self.session.collect_redfish(record)
        self.session.finish(record)
        return record


# --- P1-2: Redfish severity must reach the canonical model -----------------
class SeverityPropagationTests(RedfishSessionCase):
    def test_critical_eventlog_is_a_canonical_fail(self):
        self.fake.eventlog_pages = [{"Members": [entry(1, "OK", "boot"), entry(2, "Critical", "CPLD_0 error")]}]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['verdict'], 'FAIL')
        self.assertEqual(record['check_summary'].get('eventlog'), 'FAIL')
        self.assertEqual(record['status'], 'FAIL')
        self.assertTrue(any(i['code'] == 'REDFISH_CRITICAL' and i['severity'] == 'FAIL'
                            for i in record['issues']))
        finding = next(i for i in record['issues'] if i['code'] == 'REDFISH_CRITICAL')
        self.assertEqual(finding['component'], 'eventlog')
        self.assertEqual(finding['evidence'], record['eventlog_meta']['evidence'])
        self.assertIn('CPLD_0', finding['detail'])
        self.assertIn('2', finding['snippet'])

    def test_warning_eventlog_is_at_least_warn_not_pass(self):
        self.fake.eventlog_pages = [{"Members": [entry(1, "OK", "boot"), entry(2, "Warning", "fan slow")]}]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['verdict'], 'WARN')
        self.assertEqual(record['status'], 'WARN')
        self.assertTrue(any(i['code'] == 'REDFISH_WARNING' and i['severity'] == 'WARN'
                            for i in record['issues']))

    def _campaign(self, record):
        return {"state": "COMPLETE", "nodes": [
            {"key": 'tray1_n1', "pre": record, "loops": [], "start": None,
             "attempts": 1, "valid_cycles": 1, "boot_confirmed": 1, "completed": 1}]}

    def test_campaign_health_fails_when_a_redfish_critical_exists(self):
        self.fake.eventlog_pages = [{"Members": [entry(2, "Critical", "CPLD_0 error")]}]
        record = self.collect()
        self.assertEqual(status(self._campaign(record))['health'], 'FAIL')

    def test_campaign_health_warns_on_redfish_warning(self):
        self.fake.eventlog_pages = [{"Members": [entry(2, "Warning", "fan slow")]}]
        record = self.collect()
        self.assertEqual(status(self._campaign(record))['health'], 'WARN')

    def test_pre_classification_of_redfish_findings(self):
        self.fake.eventlog_pages = [{"Members": [entry(2, "Critical", "same fault")]}]
        pre = self.collect()
        loop = copy.deepcopy(pre)
        loop['phase'] = 'LOOP'
        loop['issues'] = [dict(i, classification='NEW') for i in pre['issues']]
        classify_against_pre(loop['issues'], issue_baseline(pre['issues']))
        crit = next(i for i in loop['issues'] if i['code'] == 'REDFISH_CRITICAL')
        self.assertEqual(crit['classification'], 'KNOWN')

    def test_new_redfish_finding_is_new(self):
        self.fake.eventlog_pages = [{"Members": [entry(1, "OK", "boot")]}]
        pre = self.collect()
        baseline = copy.deepcopy([i for i in pre['issues'] if i['code'] == 'REDFISH_CRITICAL'])
        # A later critical-only event set not present in the PRE baseline.
        self.fake.eventlog_pages = [{"Members": [entry(9, "Critical", "fresh fault")]}]
        loop = self.session.node['pre']
        self.session.collect_redfish(loop)
        self.session.finish(loop)
        loop['phase'] = 'LOOP'
        classify_against_pre(loop['issues'], issue_baseline(baseline))
        crit = next(i for i in loop['issues'] if i['code'] == 'REDFISH_CRITICAL')
        self.assertEqual(crit['classification'], 'NEW')


# --- P1-4: discovery failure is UNAVAILABLE, not NOT PRESENT ---------------
class DiscoveryFailureTests(RedfishSessionCase):
    def test_logservices_timeout_is_unavailable_not_absent(self):
        self.fake.logservices = Command(124, 'timeout', 'RESPONSE_LOST')
        record = self.collect()
        meta = record['eventlog_meta']
        self.assertIsNone(meta['present'])
        self.assertEqual(meta['status'], 'UNAVAILABLE')
        self.assertEqual(record['status'], 'FAIL')
        self.assertIn('REDFISH_UNAVAILABLE', [i['code'] for i in record['issues']])
        # The canonical FAIL issue wins the check summary; what matters is that
        # an undiscoverable service is never rendered as a verified PASS.
        self.assertNotEqual(record['check_summary'].get('eventlog'), 'PASS')

    def test_logservices_http_500_is_unavailable(self):
        self.fake.logservices = Command(500, 'server error', 'HTTP_ERROR', http_status=500)
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['status'], 'UNAVAILABLE')
        self.assertEqual(record['status'], 'FAIL')

    def test_logservices_malformed_is_unavailable(self):
        self.fake.logservices = Command(0, '{"Members":')
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['status'], 'UNAVAILABLE')
        self.assertEqual(record['status'], 'FAIL')

    def test_logservices_members_wrong_type_is_unavailable(self):
        self.fake.logservices = Command(0, json.dumps({"Members": "not-an-array"}))
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['status'], 'UNAVAILABLE')
        self.assertEqual(record['status'], 'FAIL')

    def test_confirmed_absent_service_is_not_a_failure(self):
        self.fake.redfish_sel_present = False
        self.fake.eventlog_pages = [{"Members": [entry(1, "OK", "boot")]}]
        record = self.collect()
        self.assertIs(record['redfish_sel_meta']['present'], False)
        self.assertEqual(record['redfish_sel_meta']['status'], 'NOT PRESENT')
        self.assertEqual(record['check_summary'].get('redfish_sel'), 'PASS')
        self.assertEqual(record['status'], 'PASS')


# --- P1-5: malformed collection is not an empty PASS -----------------------
class MalformedCollectionTests(RedfishSessionCase):
    def test_members_not_a_list_is_collection_failure(self):
        self.fake.eventlog_pages = [{"Members": "not-an-array"}]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['status'], 'FAILED')
        self.assertEqual(record['status'], 'FAIL')
        self.assertIn('REDFISH_COLLECTION_FAILED', [i['code'] for i in record['issues']])
        self.assertNotEqual(record['check_summary'].get('eventlog'), 'PASS')

    def test_truncated_json_is_collection_failure(self):
        self.fake.eventlog_pages = [Command(0, '{"Members": [')]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['status'], 'FAILED')
        self.assertEqual(record['status'], 'FAIL')

    def test_missing_members_key_is_collection_failure(self):
        self.fake.eventlog_pages = [{}]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['status'], 'FAILED')
        self.assertNotEqual(record['status'], 'PASS')

    def test_valid_empty_collection_is_pass(self):
        self.fake.eventlog_pages = [{"Members": []}]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['status'], 'COLLECTED')
        self.assertEqual(record['status'], 'PASS')


# --- P1-6: pagination ------------------------------------------------------
class PaginationTests(RedfishSessionCase):
    def test_second_page_critical_makes_verdict_fail(self):
        self.fake.eventlog_pages = [
            {"Members": [entry(1, "OK", "boot")],
             "Members@odata.nextLink": "/redfish/v1/Systems/System_0/LogServices/EventLog/Entries?page=2"},
            {"Members": [entry(2, "Critical", "cpl0 err")]},
        ]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['verdict'], 'FAIL')
        self.assertEqual(record['eventlog_meta']['counts']['Critical'], 1)
        self.assertEqual(record['status'], 'FAIL')
        self.assertEqual(len(record['eventlog_entries']), 2)

    def test_page2_failure_is_incomplete_not_pass(self):
        self.fake.eventlog_pages = [
            {"Members": [entry(1, "OK", "boot")],
             "Members@odata.nextLink": "/redfish/v1/Systems/System_0/LogServices/EventLog/Entries?page=2"},
            Command(500, 'server error', 'HTTP_ERROR', http_status=500),
        ]
        record = self.collect()
        meta = record['eventlog_meta']
        self.assertFalse(meta['complete'])
        self.assertEqual(meta['status'], 'FAILED')
        self.assertEqual(record['status'], 'FAIL')
        self.assertNotEqual(record['check_summary'].get('eventlog'), 'PASS')
        self.assertEqual(len(record['eventlog_entries']), 1)

    def test_pagination_loop_is_bounded(self):
        link = "/redfish/v1/Systems/System_0/LogServices/EventLog/Entries"
        page = {"Members": [], "Members@odata.nextLink": link}
        self.fake.eventlog_pages = [page, page, page]
        record = self.collect()
        self.assertFalse(record['eventlog_meta']['complete'])
        self.assertEqual(record['eventlog_meta']['status'], 'FAILED')

    def test_pagination_max_pages_is_bounded(self):
        self.assertLessEqual(self.session.REDFISH_MAX_PAGES, 50)
        seen = []

        def pages():
            i = 0
            while True:
                i += 1
                seen.append(i)
                yield {"Members": [entry(i, "OK", f"e{i}")],
                       "Members@odata.nextLink": f"/redfish/v1/x/Entries?page={i}"}
        self.fake.eventlog_pages = _LazyPages(pages())
        record = self.collect()
        self.assertFalse(record['eventlog_meta']['complete'])
        self.assertLessEqual(len(seen), self.session.REDFISH_MAX_PAGES + 1)


class _LazyPages:
    """List-like whose [0] yields a fresh page each time (tests the page cap)."""
    def __init__(self, gen):
        self._gen = gen
        self._exhausted = None
    def __len__(self):
        return 1
    def __getitem__(self, index):
        try:
            payload = next(self._gen)
        except StopIteration:
            payload = self._exhausted or {"Members": []}
        self._exhausted = payload
        return Command(0, json.dumps(payload))


# --- P2-1: delta requires valid+complete on both sides ---------------------
class DeltaValidityTests(RedfishSessionCase):
    EVENTLOG = '/redfish/v1/Systems/System_0/LogServices/EventLog/Entries'

    def test_before_failure_makes_delta_unavailable(self):
        record = self.session.node['pre']
        self.fake.entries_fail_paths[self.EVENTLOG] = Command(500, 'err', 'HTTP_ERROR', http_status=500)
        self.session._redfish_before_snapshot(record)
        self.assertFalse(record['redfish_before']['eventlog_valid'])
        del self.fake.entries_fail_paths[self.EVENTLOG]
        self.fake.eventlog_pages = [{"Members": [entry(1, "OK", "boot"), entry(2, "Critical", "new")]}]
        self.session.collect_redfish(record)
        self.session._redfish_loop_delta(record)
        delta = record['eventlog_meta']['delta']
        self.assertEqual(delta['status'], 'UNAVAILABLE')
        self.assertIsNone(delta['new_count'])

    def test_post_failure_makes_delta_unavailable(self):
        record = self.session.node['pre']
        self.session._redfish_before_snapshot(record)
        self.fake.eventlog_pages = [Command(500, 'err', 'HTTP_ERROR', http_status=500)]
        self.session.collect_redfish(record)
        self.session._redfish_loop_delta(record)
        delta = record['eventlog_meta']['delta']
        self.assertEqual(delta['status'], 'UNAVAILABLE')
        self.assertIsNone(delta['new_count'])

    def test_incomplete_post_makes_delta_unavailable(self):
        record = self.session.node['pre']
        self.session._redfish_before_snapshot(record)
        self.fake.eventlog_pages = [
            {"Members": [entry(1, "OK", "boot")],
             "Members@odata.nextLink": "/redfish/v1/x/Entries?page=2"},
            Command(500, 'err', 'HTTP_ERROR', http_status=500),
        ]
        self.session.collect_redfish(record)
        self.session._redfish_loop_delta(record)
        self.assertEqual(record['eventlog_meta']['delta']['status'], 'UNAVAILABLE')
        self.assertIsNone(record['eventlog_meta']['delta']['new_count'])

    def test_before_malformed_makes_delta_unavailable(self):
        record = self.session.node['pre']
        self.fake.entries_fail_paths[self.EVENTLOG] = Command(0, '{"Members": "x"}')
        self.session._redfish_before_snapshot(record)
        self.assertFalse(record['redfish_before']['eventlog_valid'])
        del self.fake.entries_fail_paths[self.EVENTLOG]
        self.fake.eventlog_pages = [{"Members": [entry(1, "OK", "boot")]}]
        self.session.collect_redfish(record)
        self.session._redfish_loop_delta(record)
        self.assertEqual(record['eventlog_meta']['delta']['status'], 'UNAVAILABLE')

    def test_both_valid_produces_compared(self):
        record = self.session.node['pre']
        self.fake.eventlog_pages = [{"Members": [entry(1, "OK", "boot")]}]
        self.session._redfish_before_snapshot(record)
        self.fake.eventlog_pages = [{"Members": [entry(1, "OK", "boot"), entry(2, "Critical", "new")]}]
        self.session.collect_redfish(record)
        self.session._redfish_loop_delta(record)
        delta = record['eventlog_meta']['delta']
        self.assertEqual(delta['status'], 'COMPARED')
        self.assertEqual(delta['new_count'], 1)


# --- Cross-cutting consistency assertions ----------------------------------
class ConsistencyTests(RedfishSessionCase):
    """canonical FAIL -> record FAIL -> campaign FAIL; unreadable != PASS."""

    def _campaign(self, record):
        return {"state": "COMPLETE", "nodes": [
            {"key": 'tray1_n1', "pre": record, "loops": [], "start": None,
             "attempts": 1, "valid_cycles": 1, "boot_confirmed": 1, "completed": 1}]}

    def test_any_fail_finding_forces_record_fail(self):
        cases = [
            [{"Members": [entry(2, "Critical", "c")]}],           # critical
            [Command(500, 'err', 'HTTP_ERROR', http_status=500)],  # collection failure
            [{"Members": "not-an-array"}],                        # malformed
        ]
        for pages in cases:
            with self.subTest(pages=pages):
                self.fake.eventlog_pages = pages
                record = self.collect()
                fails = [i for i in record['issues'] if i['severity'] == 'FAIL']
                self.assertTrue(fails)
                self.assertTrue(record['status'] != 'PASS')
                self.assertEqual(record['status'], 'FAIL')

    def test_campaign_health_not_pass_with_valid_fail_finding(self):
        self.fake.eventlog_pages = [{"Members": [entry(2, "Critical", "c")]}]
        record = self.collect()
        self.assertNotEqual(status(self._campaign(record))['health'], 'PASS')

    def test_unavailable_never_rendered_pass(self):
        self.fake.logservices = Command(124, 'timeout', 'RESPONSE_LOST')
        record = self.collect()
        self.assertNotEqual(record['status'], 'PASS')
        self.assertNotEqual(record['check_summary'].get('eventlog'), 'PASS')

    def test_four_states_are_distinct(self):
        record = self.session.node['pre']
        # (1) genuinely absent (valid listing, no SEL) -> NOT PRESENT, not a fail
        self.fake.redfish_sel_present = False
        self.fake.eventlog_pages = [{"Members": []}]
        self.session.collect_redfish(record); self.session.finish(record)
        self.assertIs(record['redfish_sel_meta']['present'], False)
        self.assertEqual(record['redfish_sel_meta']['status'], 'NOT PRESENT')
        self.assertEqual(record['status'], 'PASS')
        # (2) collection failure -> FAILED / FAIL, never "empty"
        record['issues'].clear()
        self.fake.redfish_sel_present = True
        self.fake.sel_pages = [Command(500, 'err', 'HTTP_ERROR', http_status=500)]
        self.session.collect_redfish(record); self.session.finish(record)
        self.assertEqual(record['redfish_sel_meta']['status'], 'FAILED')
        self.assertEqual(record['status'], 'FAIL')
        # (3) collected successfully with no events -> COLLECTED / PASS
        record['issues'].clear()
        self.fake.sel_pages = [{"Members": []}]
        self.session.collect_redfish(record); self.session.finish(record)
        self.assertEqual(record['redfish_sel_meta']['status'], 'COLLECTED')
        self.assertEqual(record['status'], 'PASS')


# --- P2-2: PRE dmesg finding points at a real evidence file ----------------
class PreDmesgEvidenceTests(RedfishSessionCase):
    def test_pre_dmesg_finding_has_existing_evidence(self):
        self.fake.hardware_failure = False
        orig = self.fake.ssh

        def ssh(t, role, cmd, timeout=60, sudo=False):
            if cmd == 'dmesg':
                return Command(0, '[   12.3] {AER: Corrected error} on 0000:01:00.0\n')
            return orig(t, role, cmd, timeout, sudo)
        self.fake.ssh = ssh
        self.session.precheck()
        record = self.session.node['pre']
        findings = [i for i in record['issues'] if i['code'].startswith('DMESG_')]
        self.assertTrue(findings, 'expected a PRE dmesg finding')
        for finding in findings:
            ev = finding['evidence']
            self.assertTrue(ev, 'finding must carry evidence')
            path = self.root / ev
            self.assertTrue(path.exists(), f'evidence file {ev} must exist')
            self.assertIn('AER', path.read_text())


if __name__ == '__main__':
    unittest.main()
