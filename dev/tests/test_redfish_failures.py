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

    Development rules enforced here (they exist so the clear-then-reread cycle
    is exercised for real, not faked):

    * ``redfish_clear`` mutates the fake store: a successful ClearLog genuinely
      empties ``eventlog_pages`` / ``sel_pages`` so the post-clear collection
      observes zero entries. A fake that only returns success would let a bug
      (pre-clear history surviving into the baseline) pass unnoticed.
    * ``routes`` lets a test serve an arbitrary path (used for LogServices
      pagination and the max-pages cap); ``requests`` counts how many times each
      path was fetched so a test can assert the cap was actually reached.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.eventlog_pages = [{"Members": [entry(1, "OK", "boot")]}]
        self.sel_pages = [{"Members": []}]
        self.logservices = None
        self.systems = None
        self.clear_status = 0
        self.entries_fail_paths = {}
        self.routes = {}
        self.requests = {}
        self.logservices_pages = None
        # Session lifecycle bookkeeping. ``live_sessions`` models the BMC's
        # session table: login adds a token, a *confirmed* logout removes it.
        # An unconfirmed logout (non-zero code / raise) must leave it behind so
        # tests can prove the leak is visible rather than silently swallowed.
        self.logins = 0
        self.logins_fail = False
        self.logout_result = None      # Command to return, or None for the default OK
        self.logout_raises = None      # exception instance to raise instead
        self.live_sessions = set()

    def redfish_login(self, target, timeout=20):
        if self.logins_fail:
            raise RuntimeError('redfish login failed (fake)')
        self.logins += 1
        token = f'FAKETOKEN{self.logins}'
        self.live_sessions.add(token)
        return token

    def redfish_logout(self, target, token, timeout=10):
        self.calls.append((target.key, 'redfish-logout', token))
        if self.logout_raises is not None:
            raise self.logout_raises
        if self.logout_result is not None:
            return self.logout_result
        self.live_sessions.discard(token)
        return Command(0, 'OK')

    def redfish_get(self, target, path, token, timeout=30):
        self.calls.append((target.key, 'redfish', path))
        bare = path.split('?', 1)[0]  # pages may carry ?page=N query strings
        self.requests[bare] = self.requests.get(bare, 0) + 1
        if path in self.entries_fail_paths:
            return self.entries_fail_paths[path]
        if path in self.routes:
            return self.routes[path]
        if bare in self.routes:
            return self.routes[bare]
        if bare == '/redfish/v1/Systems':
            if self.systems is not None:
                return self.systems
            return Command(0, json.dumps({"Members": [{"@odata.id": "/redfish/v1/Systems/System_0"}]}))
        if bare.endswith('/LogServices'):
            if self.logservices_pages is not None:
                return self._page(self.logservices_pages)
            if self.logservices is not None:
                return self.logservices
            members = [{"@odata.id": "/redfish/v1/Systems/System_0/LogServices/EventLog"}]
            if self.redfish_sel_present:
                members.append({"@odata.id": "/redfish/v1/Systems/System_0/LogServices/SEL"})
            return Command(0, json.dumps({"Members": members}))
        if bare.endswith('/EventLog/Entries'):
            return self._page(self.eventlog_pages)
        if bare.endswith('/SEL/Entries'):
            return self._page(self.sel_pages)
        return Command(127, 'Unsupported fake Redfish path: ' + path)

    def _page(self, pages):
        payload = pages[0] if isinstance(pages, _LazyPages) else (pages.pop(0) if len(pages) > 1 else pages[0])
        if isinstance(payload, Command):
            return payload
        return Command(0, json.dumps(payload))

    def redfish_clear(self, target, path, token, timeout=30):
        self.calls.append((target.key, 'redfish-clear', path))
        if self.clear_status == 0:
            # Really clear the store so the next read sees an empty log.
            if path.endswith('/EventLog/Actions/LogService.ClearLog'):
                self.eventlog_pages = [{"Members": []}]
            elif path.endswith('/SEL/Actions/LogService.ClearLog'):
                self.sel_pages = [{"Members": []}]
            return Command(0, 'OK')
        return Command(self.clear_status, 'clear rejected')


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
        # The cap test must actually reach the cap: the fake serves every page
        # path (a link that the fake did not recognise would fail on page 1 for
        # an unrelated "unsupported path" reason and pass for the wrong reason).
        self.assertLessEqual(self.session.REDFISH_MAX_PAGES, 50)
        entries_path = '/redfish/v1/Systems/System_0/LogServices/EventLog/Entries'
        generated = []

        def pages():
            i = 0
            while True:
                i += 1
                generated.append(i)
                yield {"Members": [entry(i, "OK", f"e{i}")],
                       "Members@odata.nextLink": f"{entries_path}?page={i}"}
        self.fake.eventlog_pages = _LazyPages(pages())
        record = self.collect()
        meta = record['eventlog_meta']
        # Reached the cap -> incomplete, and the engine made exactly MAX_PAGES
        # requests for that path (not one, and not an unbounded number).
        self.assertFalse(meta['complete'])
        self.assertEqual(meta['status'], 'FAILED')
        self.assertIn('exceeded', meta['reason'])
        self.assertEqual(self.fake.requests.get(entries_path), self.session.REDFISH_MAX_PAGES)
        self.assertEqual(len(generated), self.session.REDFISH_MAX_PAGES)
        # Entries gathered before the cap are retained for evidence.
        self.assertEqual(len(record['eventlog_entries']), self.session.REDFISH_MAX_PAGES)


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


# ===========================================================================
# Round-2 regressions
# ===========================================================================

class CleanStartTests(RedfishSessionCase):
    """Pre-clear history must not pollute the PRE baseline (clean-start)."""

    def precheck_like(self):
        """Run the real PRE clean-state + capture pipeline on the fake."""
        record = self.session.node['pre']
        self.session._prepare_clean_state(record)
        self.session.capture(record)
        self.session.finish(record)
        return record

    def test_clear_fake_really_empties_the_store(self):
        # (A) The fake must genuinely clear, else the clear->reread cycle is
        #     faked and a history-leak bug would pass unnoticed.
        self.fake.eventlog_pages = [{"Members": [entry(1, "Critical", "old fault")]}]
        self.fake.redfish_clear(base.target(), '/redfish/v1/Systems/System_0/LogServices/EventLog/Actions/LogService.ClearLog', 'tok')
        record = self.session.node['pre']
        self.session.collect_redfish(record)
        self.assertEqual(record['eventlog_entries'], [], 'ClearLog must empty the fake event store')

    def test_no_history_leak_after_successful_clear(self):
        # (B) Old Critical -> successful clear -> PRE sees no new events: must
        #     not leave a historical REDFISH_CRITICAL, and must not FAIL on it.
        self.fake.eventlog_pages = [{"Members": [entry(1, "Critical", "historical CPLD fault")]}]
        record = self.precheck_like()
        self.assertEqual(record['eventlog_meta']['verdict'], 'PASS')
        self.assertEqual(record['eventlog_meta']['entries'], [])
        self.assertNotIn('REDFISH_CRITICAL', [i['code'] for i in record['issues']])

    def test_new_critical_after_clear_fails_pre(self):
        # (C) History cleared, then a genuinely new Critical appears -> FAIL and
        #     the evidence must contain the new event.
        self.fake.eventlog_pages = [{"Members": [entry(1, "Critical", "old fault")]}]
        record = self.session.node['pre']
        self.session._prepare_clean_state(record)
        # New event appears between clear and the PRE capture.
        self.fake.eventlog_pages = [{"Members": [entry(7, "Critical", "fresh post-clear fault")]}]
        self.session.capture(record)
        self.session.finish(record)
        self.assertEqual(record['status'], 'FAIL')
        crit = [i for i in record['issues'] if i['code'] == 'REDFISH_CRITICAL']
        self.assertEqual(len(crit), 1)
        evid = crit[0]['evidence']
        self.assertTrue((self.root / evid).exists())
        text = (self.root / evid).read_text()
        self.assertIn('fresh post-clear fault', text)
        self.assertIn('7', text)

    def test_clear_failure_is_traceable(self):
        # (D) A failed ClearLog must still surface as a finding.
        self.fake.eventlog_pages = [{"Members": [entry(1, "Critical", "old fault")]}]
        self.fake.clear_status = 500
        record = self.session.node['pre']
        self.session._prepare_clean_state(record)
        codes = [i['code'] for i in record['issues']]
        self.assertIn('REDFISH_CLEAR_FAILED', codes)
        self.assertEqual(record['eventlog_clear']['status'], 'FAILED')

    def test_retained_history_evidence_is_separate_and_immutable(self):
        # (E) The historical finding's evidence must exist, carry the event, and
        #     must not be overwritten by the later post-clear capture.
        self.fake.eventlog_pages = [{"Members": [entry(3, "Critical", "historical fault")]}]
        record = self.session.node['pre']
        self.session._prepare_clean_state(record)
        preclear = record['eventlog_meta']['evidence'] if record.get('eventlog_meta') else None
        # The clean-state read used a separate file, and its content is preserved.
        preclear_rel = record['redfish_preclear']['eventlog']['evidence']
        self.assertTrue((self.root / preclear_rel).exists())
        self.assertIn('historical fault', (self.root / preclear_rel).read_text())
        # The later capture writes its own file and must not clobber the above.
        self.session.capture(record)
        self.session.finish(record)
        self.assertTrue((self.root / preclear_rel).exists())
        self.assertIn('historical fault', (self.root / preclear_rel).read_text())
        self.assertNotEqual(record['eventlog_meta']['evidence'], preclear_rel)

    def test_precheck_full_pipeline_has_no_history_finding(self):
        # End-to-end through precheck(): the historical Critical is gone from the
        # baseline issue set.
        self.fake.eventlog_pages = [{"Members": [entry(1, "Critical", "historical fault")]}]
        self.session.precheck()
        record = self.session.node['pre']
        self.assertNotIn('REDFISH_CRITICAL', [i['code'] for i in record['issues']])
        self.assertEqual(record['eventlog_meta']['entries'], [])


class MemberValidityTests(RedfishSessionCase):
    """Member elements must be validated, not silently filtered."""

    def test_non_object_members_are_not_a_pass(self):
        # (A) [null, 7] is a corrupt collection.
        self.fake.eventlog_pages = [{"Members": [None, 7]}]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['status'], 'FAILED')
        self.assertEqual(record['status'], 'FAIL')
        self.assertNotEqual(record['check_summary'].get('eventlog'), 'PASS')

    def test_non_object_members_do_not_authorize_clear(self):
        # (A) A corrupt collection must not drive ClearLog.
        self.fake.eventlog_pages = [{"Members": [None, 7]}]
        record = self.session.node['pre']
        self.session.collect_redfish(record, clear=True)
        self.assertFalse([c for c in self.fake.calls if c[1] == 'redfish-clear'],
                         'ClearLog must not be sent for an unreadable collection')

    def test_legit_empty_collection_is_pass(self):
        # (B) A real empty collection is a success with zero events.
        self.fake.eventlog_pages = [{"Members": []}]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['status'], 'COLLECTED')
        self.assertEqual(record['status'], 'PASS')

    def test_bare_reference_is_kept_not_silently_dropped(self):
        # (C) A member that is only an @odata.id must be resolved (or at least
        #     not silently counted as zero events).
        ref_path = '/redfish/v1/Systems/System_0/LogServices/EventLog/Entries/9'
        self.fake.routes[ref_path] = Command(0, json.dumps(entry(9, "Critical", "via reference")))
        self.fake.eventlog_pages = [{"Members": [{"@odata.id": ref_path}]}]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['verdict'], 'FAIL')
        self.assertEqual(record['status'], 'FAIL')
        self.assertEqual(record['eventlog_entries'][0]['id'], '9')

    def test_expanded_critical_entry_is_kept(self):
        self.fake.eventlog_pages = [{"Members": [entry(4, "Critical", "expanded fault")]}]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['verdict'], 'FAIL')
        self.assertEqual(record['eventlog_entries'][0]['id'], '4')


class LogServicesPaginationTests(RedfishSessionCase):
    """LogServices discovery must read every page before declaring absence."""

    def test_eventlog_on_second_logservices_page_is_found(self):
        # (D) Page 1 only has OtherLog; page 2 has EventLog with a Critical.
        self.fake.logservices_pages = [
            {"Members": [{"@odata.id": "/redfish/v1/Systems/System_0/LogServices/OtherLog"}],
             "Members@odata.nextLink": "/redfish/v1/Systems/System_0/LogServices?page=2"},
            {"Members": [{"@odata.id": "/redfish/v1/Systems/System_0/LogServices/EventLog"}]},
        ]
        self.fake.eventlog_pages = [{"Members": [entry(5, "Critical", "late log critical")]}]
        record = self.collect()
        self.assertEqual(record['eventlog_meta']['present'], True)
        self.assertEqual(record['eventlog_meta']['verdict'], 'FAIL')
        self.assertEqual(record['status'], 'FAIL')
        self.assertIn('REDFISH_CRITICAL', [i['code'] for i in record['issues']])

    def test_logservices_second_page_failure_is_not_absent(self):
        # (E) Page 2 failing means discovery is incomplete -> NOT NOT-PRESENT.
        self.fake.logservices_pages = [
            {"Members": [{"@odata.id": "/redfish/v1/Systems/System_0/LogServices/OtherLog"}],
             "Members@odata.nextLink": "/redfish/v1/Systems/System_0/LogServices?page=2"},
            Command(500, 'server error', 'HTTP_ERROR', http_status=500),
        ]
        record = self.collect()
        self.assertIsNone(record['eventlog_meta']['present'])
        self.assertEqual(record['eventlog_meta']['status'], 'UNAVAILABLE')
        self.assertEqual(record['status'], 'FAIL')
        self.assertNotEqual(record['check_summary'].get('eventlog'), 'PASS')


class PartialEvidenceTests(RedfishSessionCase):
    """Already-fetched events keep their Id/Severity/Message in evidence."""

    def _partial(self, second_page):
        self.fake.eventlog_pages = [
            {"Members": [entry(1, "Critical", "page1 critical message")],
             "Members@odata.nextLink": "/redfish/v1/Systems/System_0/LogServices/EventLog/Entries?page=2"},
            second_page,
        ]
        record = self.collect()
        evid = record['eventlog_meta']['evidence']
        path = self.root / evid
        return record, path, path.read_text()

    def test_http_failure_keeps_first_page_evidence(self):
        # (A/B/C) page 2 -> HTTP 500.
        record, path, text = self._partial(Command(500, 'boom', 'HTTP_ERROR', http_status=500))
        self.assertFalse(record['eventlog_meta']['complete'])
        self.assertNotEqual(record['eventlog_meta']['verdict'], 'PASS')
        self.assertTrue(path.exists())
        self.assertIn('page1 critical message', text)
        self.assertIn('Critical', text)
        self.assertIn('1 |', text)
        # The failure reason is retained, not just a count.
        self.assertIn('HTTP', text)

    def test_malformed_page_keeps_first_page_evidence(self):
        # (D) page 2 malformed.
        record, path, text = self._partial(Command(0, '{"Members": ['))
        self.assertFalse(record['eventlog_meta']['complete'])
        self.assertNotEqual(record['eventlog_meta']['verdict'], 'PASS')
        self.assertIn('page1 critical message', text)
        self.assertIn('Critical', text)

    def test_max_pages_keeps_first_page_evidence(self):
        # (D) genuinely reaching the page cap.
        entries_path = '/redfish/v1/Systems/System_0/LogServices/EventLog/Entries'
        generated = []

        def pages():
            i = 1
            generated.append((i, entry(1, "Critical", "capped critical message")))
            yield {"Members": [entry(1, "Critical", "capped critical message")],
                   "Members@odata.nextLink": f"{entries_path}?page=2"}
            while True:
                i += 1
                generated.append((i, entry(i, "OK", f"e{i}")))
                yield {"Members": [entry(i, "OK", f"e{i}")],
                       "Members@odata.nextLink": f"{entries_path}?page={i+1}"}
        self.fake.eventlog_pages = _LazyPages(pages())
        record = self.collect()
        meta = record['eventlog_meta']
        self.assertFalse(meta['complete'])
        self.assertIn('exceeded', meta['reason'])
        text = (self.root / meta['evidence']).read_text()
        self.assertIn('capped critical message', text)
        self.assertIn('Critical', text)


class SeverityTransitionTests(RedfishSessionCase):
    """Same event Warning -> Critical compares as the same event."""

    def _collect_phase(self, sev, msg, idx, phase='PRE', forced_loop=None):
        self.fake.eventlog_pages = [{"Members": [entry(idx, sev, msg)]}]
        record = self.session.node['pre']
        if phase != 'PRE':
            record['phase'] = phase
            record['loop'] = forced_loop or 1
        self.session.collect_redfish(record)
        self.session.finish(record)
        return record

    def test_warning_to_critical_is_worsened(self):
        pre = self._collect_phase("Warning", "same event", 5)
        baseline = issue_baseline(pre['issues'])
        loop = self._collect_phase("Critical", "same event", 5, phase='LOOP')
        classify_against_pre(loop['issues'], baseline)
        crit = next(i for i in loop['issues'] if i['code'] == 'REDFISH_CRITICAL')
        self.assertEqual(crit['classification'], 'WORSENED')
        self.assertEqual(loop['status'], 'FAIL')

    def test_critical_to_critical_is_known(self):
        pre = self._collect_phase("Critical", "same event", 5)
        baseline = issue_baseline(pre['issues'])
        loop = self._collect_phase("Critical", "same event", 5, phase='LOOP')
        classify_against_pre(loop['issues'], baseline)
        crit = next(i for i in loop['issues'] if i['code'] == 'REDFISH_CRITICAL')
        self.assertEqual(crit['classification'], 'KNOWN')

    def test_different_event_is_new(self):
        pre = self._collect_phase("Warning", "event A", 1)
        baseline = issue_baseline(pre['issues'])
        loop = self._collect_phase("Critical", "event B", 2, phase='LOOP')
        classify_against_pre(loop['issues'], baseline)
        crit = next(i for i in loop['issues'] if i['code'] == 'REDFISH_CRITICAL')
        self.assertEqual(crit['classification'], 'NEW')


class RedfishSessionLifecycleTests(RedfishSessionCase):
    """A login that succeeds must always be paired with a logout attempt, even
    when discovery fails *after* the token was issued.

    ``_redfish_discover`` logs in first and only then reads /Systems. Until the
    fix, any exception raised between login and the ``try`` in
    ``_redfish_session`` escaped without a logout, leaking one BMC session per
    failed discovery on a long, multi-node, multi-loop campaign.
    """

    def logouts(self):
        return [c for c in self.fake.calls if c[1] == 'redfish-logout']

    def enter_session(self, record=None):
        """Enter the real context manager: the seam under test. Entering must
        log in; leaving (normally or via an exception) must release the session."""
        return self.session._redfish_session(record if record is not None else self.session.node['pre'])

    def test_systems_http_500_still_attempts_logout(self):
        # (A) login succeeds, /Systems returns HTTP 500 -> discovery raises, yet
        #     the session that was just opened must still be released.
        self.fake.systems = Command(500, 'server error', 'HTTP_ERROR', http_status=500)
        with self.assertRaises(RuntimeError):
            with self.enter_session():
                pass
        self.assertEqual(self.fake.logins, 1)
        self.assertEqual(len(self.logouts()), 1, 'a successful login must be logged out exactly once')

    def test_systems_malformed_json_still_attempts_logout(self):
        # (B) login succeeds, /Systems body is malformed.
        self.fake.systems = Command(0, '{"Members": [')
        with self.assertRaises(RuntimeError):
            with self.enter_session():
                pass
        self.assertEqual(self.fake.logins, 1)
        self.assertEqual(len(self.logouts()), 1)

    def test_discovery_exception_still_runs_cleanup(self):
        # (C) An exception raised inside the caller's collection (after the
        #     token was issued) must still trigger cleanup.
        with self.assertRaises(ValueError):
            with self.enter_session():
                raise ValueError('entry collection blew up')
        self.assertEqual(self.fake.logins, 1)
        self.assertEqual(len(self.logouts()), 1)

    def test_logservices_incomplete_still_releases_session(self):
        # (C/D) A non-raising incomplete discovery (LogServices page failure)
        #       still has to release the session it opened.
        self.fake.logservices_pages = [Command(500, 'boom', 'HTTP_ERROR', http_status=500)]
        with self.enter_session():
            pass
        self.assertEqual(self.fake.logins, 1)
        self.assertEqual(len(self.logouts()), 1)

    def test_repeated_collections_do_not_accumulate_sessions(self):
        # (D) A fake BMC's unreleased-session table must not grow across
        #     repeated collections: every login is matched by a logout.
        for _ in range(3):
            self.session.collect_redfish(self.session.node['pre'])
        for _ in range(3):
            self.session._redfish_before_snapshot(self.session.node['pre'])
        self.assertEqual(len(self.logouts()), self.fake.logins)
        self.assertEqual(self.fake.live_sessions, set(), 'no session may remain open on the BMC')

    def test_login_failure_does_not_fake_logout(self):
        # (E) When login itself fails there is no session to release; a logout
        #     attempt against a non-existent token would be a fabricated event.
        self.fake.logins_fail = True
        with self.assertRaises(RuntimeError):
            with self.enter_session():
                pass
        self.assertEqual(self.fake.logins, 0)
        self.assertEqual(self.logouts(), [])

    def test_cleanup_failure_does_not_mask_discovery_exception(self):
        # (C/E) If logout also fails while discovery is raising, the original
        #       discovery exception must win (cleanup never masks the cause).
        self.fake.systems = Command(500, 'server error', 'HTTP_ERROR', http_status=500)
        self.fake.logout_raises = RuntimeError('logout transport exploded')
        with self.assertRaises(RuntimeError) as ctx:
            with self.enter_session():
                pass
        self.assertIn('Systems unavailable', str(ctx.exception))


class LogoutCommandTests(RedfishSessionCase):
    """Logout failures that are *returned* as a non-zero Command (not raised)
    must be surfaced as a WARN, must not downgrade a valid collection, and must
    never re-trigger a power/cycle action.
    """

    def logout_codes(self, record):
        return [i for i in record['issues'] if i['code'] == 'REDFISH_LOGOUT_FAILED']

    def test_http_500_logout_command_is_warn(self):
        # (A) transport returns Command(code=500) instead of raising.
        self.fake.logout_result = Command(500, 'server error', 'HTTP_ERROR', http_status=500)
        record = self.collect()
        warn = self.logout_codes(record)
        self.assertEqual(len(warn), 1)
        self.assertEqual(warn[0]['severity'], 'WARN')
        # A WARN for an unconfirmed release is allowed, but the valid collection
        # must NOT be turned into a FAIL.
        self.assertNotEqual(record['status'], 'FAIL')
        self.assertNotIn('REDFISH_COLLECTION_FAILED', [i['code'] for i in record['issues']])

    def test_timeout_logout_keeps_collection_and_original_issue(self):
        # (B) RESPONSE_LOST / timeout: keep the collection result and any
        #     original problem untouched.
        self.fake.logout_result = Command(124, 'timeout', 'RESPONSE_LOST')
        record = self.collect()
        self.assertEqual(len(self.logout_codes(record)), 1)
        self.assertNotIn('REDFISH_COLLECTION_FAILED', [i['code'] for i in record['issues']])

    def test_logout_raise_does_not_override_original_exception(self):
        # (C) A raising logout must not mask a discovery/collection failure.
        self.fake.systems = Command(500, 'server error', 'HTTP_ERROR', http_status=500)
        self.fake.logout_raises = RuntimeError('logout exploded')
        with self.assertRaises(RuntimeError) as ctx:
            with self.session._redfish_session(self.session.node['pre']):
                pass
        self.assertIn('Systems unavailable', str(ctx.exception))

    def test_logout_failure_does_not_trigger_power_action(self):
        # (D) A failed logout must not re-send any power/cycle command.
        actions = []
        self.fake.on_action = lambda: actions.append(1)
        self.fake.logout_result = Command(500, 'server error', 'HTTP_ERROR', http_status=500)
        self.session.precheck()
        self.session.start()
        record = self.session.one_loop(1)
        self.assertEqual(len(actions), 1, 'exactly the loop\'s own cycle action may occur')
        self.assertGreaterEqual(len(self.logout_codes(record)), 1)


class HttpGateTests(unittest.TestCase):
    """_redfish must never report success without a confirmed HTTP success."""

    def _run(self, status_text, body='', exit_code=0):
        import os
        import stat
        import tempfile
        from cycle_transport import Transport
        tmpd = tempfile.mkdtemp()
        p = Path(tmpd) / 'curl'
        p.write_text("#!/usr/bin/env sh\ncat <<'B'\n" + body + "\nB\nprintf '\\n__VERA_HTTP_STATUS__:" + status_text + "'\nexit " + str(exit_code) + "\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
        tr = Transport({}, Path(tmpd) / 'kh')
        old = os.environ['PATH']
        os.environ['PATH'] = tmpd + os.pathsep + old
        try:
            return tr._redfish(['https://bmc/x'], 5)
        finally:
            os.environ['PATH'] = old

    def test_redirect_is_not_success(self):
        r = self._run('302')
        self.assertNotEqual(r.code, 0)
        self.assertEqual(r.state, 'HTTP_REDIRECT')
        self.assertEqual(r.http_status, 302)

    def test_missing_marker_is_not_success(self):
        import os
        import stat
        import tempfile
        from cycle_transport import Transport
        tmpd = tempfile.mkdtemp()
        p = Path(tmpd) / 'curl'
        p.write_text("#!/usr/bin/env sh\necho 'connection refused'\nexit 0\n")
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
        tr = Transport({}, Path(tmpd) / 'kh')
        old = os.environ['PATH']
        os.environ['PATH'] = tmpd + os.pathsep + old
        try:
            r = tr._redfish(['https://bmc/x'], 5)
        finally:
            os.environ['PATH'] = old
        self.assertNotEqual(r.code, 0, 'missing status marker must not be a success')

    def test_malformed_marker_is_not_success(self):
        r = self._run('not-a-number')
        self.assertNotEqual(r.code, 0)
        self.assertEqual(r.state, 'HTTP_ERROR')

    def test_status_zero_is_not_success(self):
        r = self._run('000')
        self.assertNotEqual(r.code, 0)
        self.assertEqual(r.state, 'HTTP_ERROR')

    def test_200_and_204_are_success(self):
        for status in ('200', '204'):
            r = self._run(status, body='{}')
            self.assertEqual(r.code, 0, f'HTTP {status} must be success')
            self.assertEqual(r.http_status, int(status))

    def test_4xx_5xx_are_failures(self):
        for status in ('400', '401', '404', '500'):
            r = self._run(status)
            self.assertNotEqual(r.code, 0, f'HTTP {status} must not be a success')
            self.assertEqual(r.state, 'HTTP_ERROR')

    def test_clear_redirect_never_succeeds(self):
        # A 302 on ClearLog must not be recorded as SUCCEEDED.
        self.fake_redirect = None
        case = RedfishSessionCase('setUp')
        case.setUp()
        try:
            case.fake.eventlog_pages = [{"Members": [entry(1, "OK", "boot")]}]
            # Force the transport-level clear to look like an unfollowed redirect.
            case.fake.clear_status = 302
            case.session.collect_redfish(case.session.node['pre'], clear=True)
            clear = case.session.node['pre']['eventlog_clear']
            self.assertEqual(clear['status'], 'FAILED')
            self.assertNotEqual(clear['code'], 0)
        finally:
            case.tearDown()


if __name__ == '__main__':
    unittest.main()
