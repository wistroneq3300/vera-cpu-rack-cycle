"""Report classification / evidence semantics regressions.

Covers the review items:
  * WORSENED removal (KNOWN/NEW only + severity-transition metadata)
  * per-loop EventLog classification (before snapshot, not PRE)
  * same-phase finding dedup (initial read + confirmation)
  * Redfish event identity (Id + Message) and Id-wrap fail-safe

Offline only. No SSH, network, apt, IPMI or hardware access.
"""
import unittest

from cycle_core import (
    aggregate_issues,
    classify_against_pre,
    compare_sensors,
    issue,
    issue_baseline,
    parse_sensors,
    redfish_delta,
)
from cycle_engine import new_record
from cycle_report import render_html


def ev(i, severity, message, created='2026-10-06T00:00:00+00:00'):
    return dict(id=str(i), severity=severity, severity_key=severity.lower(),
                message=message, created=created)


def redfish_issue(i, message, severity, component='eventlog'):
    item = issue('REDFISH_CRITICAL' if severity == 'FAIL' else 'REDFISH_WARNING',
                 component, f"Redfish EventLog: {i} {message}", severity=severity)
    item['identity'] = f"EventLog|{i}|{message}"
    return item


class WorsenedRemovalTests(unittest.TestCase):
    def test_pre_issue_recurring_is_known(self):
        pre = [issue('BF4_MISSING', 'BF4', 'missing')]
        items = classify_against_pre(
            [issue('BF4_MISSING', 'BF4', 'still missing', 'FAIL')],
            issue_baseline(pre))
        self.assertEqual(items[0]['classification'], 'KNOWN')
        self.assertNotEqual(items[0]['classification'], 'WORSENED')

    def test_pre_warn_escalated_to_fail_is_new_with_transition(self):
        pre = [issue('SENSOR_X', 'sensorA', 'warn', 'WARN')]
        items = classify_against_pre(
            [issue('SENSOR_X', 'sensorA', 'warn', 'FAIL')],
            issue_baseline(pre))
        self.assertEqual(items[0]['classification'], 'NEW')
        self.assertTrue(items[0].get('severity_changed'))
        self.assertEqual(items[0].get('previous_severity'), 'WARN')
        self.assertEqual(items[0].get('current_severity'), 'FAIL')

    def test_count_increase_does_not_change_classification(self):
        pre = [issue('SENSOR_X', 'sensorA', 'same', 'WARN')]
        items = classify_against_pre(
            [issue('SENSOR_X', 'sensorA', 'same', 'WARN')],
            issue_baseline(pre))
        self.assertEqual(items[0]['classification'], 'KNOWN')

    def test_fail_recurring_stays_known(self):
        pre = [issue('BF4_MISSING', 'BF4', 'missing', 'FAIL')]
        items = classify_against_pre(
            [issue('BF4_MISSING', 'BF4', 'missing', 'FAIL')], issue_baseline(pre))
        self.assertEqual(items[0]['classification'], 'KNOWN')

    def test_no_worsened_anywhere_in_aggregate(self):
        pre = new_record('PRE')
        loop1 = new_record('LOOP 1')
        pre['issues'] = [issue('SENSOR_X', 'sensorA', 'warn', 'WARN')]
        loop1['issues'] = [issue('SENSOR_X', 'sensorA', 'warn', 'FAIL')]
        merged = aggregate_issues({'nodes': [{'key': 't_n1', 'pre': pre, 'loops': [loop1]}]})
        for m in merged:
            self.assertNotEqual(m['classification'], 'WORSENED')


class EventLogPerLoopTests(unittest.TestCase):
    def test_event_new_only_on_first_loop(self):
        # Loop 2 introduces event 48; loop 3 before snapshot already has it.
        pre = new_record('PRE')
        loop2 = new_record('LOOP 2')
        loop3 = new_record('LOOP 3')
        loop2['issues'] = [redfish_issue(48, 'svc fail', 'FAIL')]
        loop2['eventlog_delta_ids'] = ['48']
        loop3['issues'] = [redfish_issue(48, 'svc fail', 'FAIL')]
        loop3['eventlog_delta_ids'] = []
        data = {'nodes': [{'key': 't_n1', 'pre': pre, 'loops': [loop2, loop3]}]}
        by_phase = {}
        for item in aggregate_issues(data):
            by_phase = item  # keep last
            self.assertNotEqual(item['classification'], 'WORSENED')
        # event 48 first seen loop2 -> NEW, loop3 -> KNOWN (not NEW)
        e48 = [i for i in aggregate_issues(data) if i['code'] == 'REDFISH_CRITICAL'][0]
        self.assertEqual(e48['classification'], 'NEW')

    def test_eventlog_falls_back_to_meta_delta_when_marker_absent(self):
        # Records captured before the top-level marker existed still classify
        # against the per-service delta stored in the meta.
        rec = new_record('LOOP 4')
        rec['issues'] = [redfish_issue(9, 'x', 'FAIL')]
        rec['eventlog_meta'] = {'delta': {'status': 'COMPARED',
                                          'new_entries': [{'id': '9', 'message': 'x'}]}}
        merged = aggregate_issues({'nodes': [{'key': 't_n1', 'pre': new_record('PRE'), 'loops': [rec]}]})
        self.assertEqual(merged[0]['classification'], 'NEW')

    def test_unavailable_delta_keeps_pre_baseline(self):
        rec = new_record('LOOP 4')
        rec['issues'] = [redfish_issue(9, 'x', 'FAIL')]
        rec['eventlog_meta'] = {'delta': {'status': 'UNAVAILABLE', 'new_entries': []}}
        merged = aggregate_issues({'nodes': [{'key': 't_n1', 'pre': new_record('PRE'), 'loops': [rec]}]})
        # No comparable delta -> falls back to PRE (absent) -> NEW.
        self.assertEqual(merged[0]['classification'], 'NEW')

    def test_eventlog_findings_carry_per_loop_delta_marker(self):
        rec = new_record('LOOP 1')
        rec['issues'] = [redfish_issue(1, 'x', 'FAIL')]
        rec['eventlog_delta_ids'] = ['1']
        merged = aggregate_issues({'nodes': [{'key': 't_n1', 'pre': new_record('PRE'), 'loops': [rec]}]})
        self.assertEqual(merged[0]['classification'], 'NEW')

    def test_eventlog_known_after_first_loop(self):
        pre = new_record('PRE')
        loop1 = new_record('LOOP 1')
        loop2 = new_record('LOOP 2')
        loop1['eventlog_delta_ids'] = ['48']
        loop1['issues'] = [redfish_issue(48, 'svc fail', 'FAIL')]
        loop2['eventlog_delta_ids'] = []
        loop2['issues'] = [redfish_issue(48, 'svc fail', 'FAIL')]
        merged = aggregate_issues({'nodes': [{'key': 't_n1', 'pre': pre, 'loops': [loop1, loop2]}]})
        e48 = [i for i in merged if i['code'] == 'REDFISH_CRITICAL'][0]
        # The event is new to the campaign (introduced in loop 1), so the group
        # is NEW; but loop 2's occurrence must be KNOWN, not re-flagged as new.
        self.assertEqual(e48['classification'], 'NEW')
        per_phase = {o['phase']: o.get('classification') for o in e48['occurrences']}
        self.assertEqual(per_phase['LOOP 1'], 'NEW')
        self.assertEqual(per_phase['LOOP 2'], 'KNOWN')


class SensorDedupTests(unittest.TestCase):
    def test_duplicate_sensor_reported_once_per_phase(self):
        baseline = parse_sensors('Temp | 30 | C | ok\nFan | 1 | RPM | ok\n')
        # Same duplicate seen in both the initial read and the confirmation read.
        initial = parse_sensors('Temp | 30 | C | ok\nTemp | 30 | C | ok\nFan | 1 | RPM | ok\n')
        confirm = parse_sensors('Temp | 30 | C | ok\nTemp | 30 | C | ok\nFan | 1 | RPM | ok\n')
        items = compare_sensors(baseline, initial, confirm)
        dups = [i for i in items if i['code'] == 'SENSOR_DUPLICATE']
        self.assertEqual(len(dups), 1)

    def test_missing_sensor_reported_once_per_phase(self):
        baseline = parse_sensors('Temp | 30 | C | ok\nFan | 1 | RPM | ok\n')
        initial = parse_sensors('Fan | 1 | RPM | ok\n')      # Temp gone
        confirm = parse_sensors('Fan | 1 | RPM | ok\n')      # still gone
        items = compare_sensors(baseline, initial, confirm)
        missing = [i for i in items if i['code'] == 'SENSOR_MISSING']
        self.assertEqual(len(missing), 1)


class EventIdentityTests(unittest.TestCase):
    def test_delta_identity_ignores_severity(self):
        # Same Id + Message + timestamp, severity escalated WARN -> Critical:
        # this is the *same* event, not a newly added record.
        prev = [ev(48, 'Warning', 'svc fail')]
        cur = [ev(48, 'Critical', 'svc fail')]
        self.assertEqual(redfish_delta(prev, cur), [])

    def test_delta_same_id_message_timestamp_is_not_new(self):
        prev = [ev(48, 'Critical', 'svc fail', created='2026-10-06T00:00:00+00:00')]
        cur = [ev(48, 'Critical', 'svc fail', created='2026-10-06T00:00:00+00:00')]
        self.assertEqual(redfish_delta(prev, cur), [])


class EventIdWrapTests(unittest.TestCase):
    def test_id_wrap_uses_timestamp_so_history_is_not_all_new(self):
        prev = [ev(i, 'OK', f'm{i}') for i in range(200, 205)]
        cur = [ev(1, 'OK', 'new1', created='2026-10-06T01:00:00+00:00')]
        new = redfish_delta(prev, cur)
        self.assertEqual([e['id'] for e in new], ['1'])

    def test_id_reuse_with_different_timestamp_is_new(self):
        prev = [ev(48, 'Critical', 'svc fail', created='2020-01-01T00:00:00+00:00')]
        cur = [ev(48, 'Critical', 'svc fail', created='2026-10-06T00:00:00+00:00')]
        new = redfish_delta(prev, cur)
        self.assertEqual(len(new), 1)


class ConsoleSummaryTests(unittest.TestCase):
    def _render(self, record):
        from neutrino_cycle import show_result
        output = []
        node = dict(key='n1', pre=new_record('PRE'), loops=[record], blocked=[])
        show_result(output.append, node, record)
        return '\n'.join(output)

    def test_eventlog_summary_one_line_with_new_and_total(self):
        rec = new_record('LOOP 3')
        rec['eventlog_meta'] = {
            'status': 'COLLECTED', 'present': True, 'valid': True, 'complete': True,
            'verdict': 'FAIL', 'counts': {'Critical': 2, 'Warning': 0, 'OK': 56},
            'delta': {'status': 'COMPARED', 'new_count': 32},
        }
        rec['issues'] = [redfish_issue(48, 'svc fail', 'FAIL')]
        text = self._render(rec)
        self.assertIn('EventLog: FAIL · Critical:2 Warning:0 OK:56 · new:32 · total:58', text)
        # The per-entry detail line must NOT be printed for eventlog findings.
        self.assertNotIn('FAIL eventlog:', text)
        self.assertNotIn('Redfish EventLog: 48', text)

    def test_benign_summary_line_is_still_printed(self):
        rec = new_record('LOOP 4')
        rec['eventlog_meta'] = {
            'status': 'COLLECTED', 'present': True, 'valid': True, 'complete': True,
            'verdict': 'PASS', 'counts': {'Critical': 0, 'Warning': 0, 'OK': 134},
            'delta': {'status': 'COMPARED', 'new_count': 19},
        }
        text = self._render(rec)
        self.assertIn('EventLog: PASS · Critical:0 Warning:0 OK:134 · new:19 · total:134', text)

    def test_sel_summary_uses_same_format(self):
        rec = new_record('LOOP 5')
        rec['redfish_sel_meta'] = {
            'status': 'COLLECTED', 'present': True, 'valid': True, 'complete': True,
            'verdict': 'WARN', 'counts': {'Critical': 0, 'Warning': 1, 'OK': 3},
            'delta': {'status': 'COMPARED', 'new_count': 1},
        }
        text = self._render(rec)
        self.assertIn('Redfish SEL: WARN · Critical:0 Warning:1 OK:3 · new:1 · total:4', text)


class HtmlRenderTests(unittest.TestCase):
    def _render(self, record):
        from test_report_semantics import campaign
        pre = new_record('PRE')
        # Reuse the offline campaign builder so the HTML renderer gets a complete,
        # valid structure (run_id, limits, target IPs, etc.).
        return render_html(campaign([pre, record]), '')

    def test_legacy_worsened_does_not_render_badge(self):
        rec = new_record('LOOP 3')
        # A finding stored with the removed WORSENED classification (legacy data).
        rec['issues'] = [dict(code='SENSOR_REMOVED', component='sensor', severity='FAIL',
                              detail='cpu0_temp_01 missing', snippet='line 9: ...',
                              classification='WORSENED')]
        html = self._render(rec)
        self.assertNotIn('WORSENED', html)
        self.assertNotIn('worsened', html.lower())
        # The finding is normalized to KNOWN and still shown (not dropped).
        self.assertIn('cpu0_temp_01 missing', html)

    def test_eventlog_summary_line_in_findings(self):
        rec = new_record('LOOP 3')
        rec['eventlog_meta'] = {
            'status': 'COLLECTED', 'present': True, 'valid': True, 'complete': True,
            'verdict': 'FAIL', 'counts': {'Critical': 2, 'Warning': 0, 'OK': 56},
            'delta': {'status': 'COMPARED', 'new_count': 32},
        }
        rec['issues'] = [redfish_issue(48, 'svc fail', 'FAIL')]
        html = self._render(rec)
        # Full event entries preserved in the per-record findings.
        self.assertIn('Redfish EventLog: 48 svc fail', html)

    def test_eventlog_detail_preserved_for_known_too(self):
        rec = new_record('LOOP 3')
        rec['eventlog_meta'] = {
            'status': 'COLLECTED', 'present': True, 'valid': True, 'complete': True,
            'verdict': 'FAIL', 'counts': {'Critical': 1, 'Warning': 0, 'OK': 10},
            'delta': {'status': 'COMPARED', 'new_count': 1},
        }
        rec['issues'] = [dict(code='REDFISH_CRITICAL', component='eventlog', severity='FAIL',
                              detail='Redfish EventLog: 12 svc down', snippet='Severity: Critical',
                              classification='KNOWN')]
        html = self._render(rec)
        # Even KNOWN eventlog findings keep their detail line in the HTML.
        self.assertIn('Redfish EventLog: 12 svc down', html)


if __name__ == '__main__':
    unittest.main()
