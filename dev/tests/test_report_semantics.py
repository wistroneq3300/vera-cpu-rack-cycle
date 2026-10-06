"""Offline regressions for report grouping, phase semantics and evidence links."""
import unittest

from cycle_core import merge_pci_devices, parse_pci, parse_pci_verbose, issue
from cycle_engine import new_record
from cycle_report import (_pci_summary, _render_pci_group, _render_sel, _render_summary_groups,
                          _finding_summary, issue_cards, record_html, render_html)


PCI = """0002:02:00.0 VGA compatible controller [0300]: ASPEED Technology, Inc. ASPEED Graphics Family [1a03:2000]
0002:21:00.0 USB controller [0c03]: Renesas Electronics Corp. uPD720201 USB 3.0 Host Controller [1912:0014]
0004:01:00.0 Non-Volatile memory controller [0108]: KIOXIA Corporation NVMe SSD Controller XD8 [1e0f:002e]
000c:01:00.0 Non-Volatile memory controller [0108]: KIOXIA Corporation Device [1e0f:001c]
0002:00:00.0 PCI bridge [0604]: Fabric bridge [10de:2f95]
"""

VERBOSE = """0002:02:00.0 VGA compatible controller
\tCapabilities: [50] MSI: Enable+
\tDeviceName: Embedded Video Controller
0002:21:00.0 USB controller
\tCapabilities: [a0] Express (v2) Endpoint
\tLnkCap: Speed 5GT/s, Width x1
\tLnkSta: Speed 5GT/s, Width x1
0004:01:00.0 Non-Volatile memory controller
\tCapabilities: [80] Express (v2) Endpoint
\tLnkCap: Speed 32GT/s, Width x4
\tLnkSta: Speed 32GT/s, Width x4
000c:01:00.0 Non-Volatile memory controller
\tCapabilities: [80] Express (v2) Endpoint
\tLnkCap: Speed 16GT/s, Width x4
\tLnkSta: Speed 16GT/s, Width x4
0002:00:00.0 PCI bridge
\tCapabilities: [80] Express (v2) Root Port
\tLnkSta: Speed 16GT/s, Width x16
"""


def campaign(records, issues=None):
    pre = records[0]
    node = dict(key='tray1_n1', target=dict(node='n1', bmc_ip='192.0.2.1', os_ip='192.0.2.2'),
                blocked=[], active=True, pre=pre, start=None, loops=[], completed=0,
                attempts=0, boot_confirmed=0, valid_cycles=0, stop_reason='', stage='')
    for record in records[1:]:
        if record['phase'] == 'START':
            node['start'] = record
        else:
            node['loops'].append(record)
    node['completed'] = sum(bool(r.get('post_complete')) for r in node['loops'])
    return dict(run_id='offline-report', state='COMPLETE', cycle_mode='power_cycle', channel='inband',
                started='2026-10-01T10:00:00+08:00', finished='2026-10-01T10:01:00+08:00',
                stop_reason='', limits={'loops': 1, 'hours': 0}, script_sha256='sha', nodes=[node],
                project='neutrino', issues=issues or [])


class ReportSemanticsTests(unittest.TestCase):
    def test_report_uses_official_two_colour_wistron_wordmark(self):
        page = render_html(campaign([new_record('PRE')]))
        self.assertIn('class="brand-mark"', page)
        self.assertIn('aria-label="Wistron"', page)
        self.assertIn('#016c8c', page)
        self.assertIn('#9acd66', page)
        self.assertNotIn('brand">Wistron', page)

    def test_pci_devices_are_data_driven_and_grouped(self):
        devices = merge_pci_devices(parse_pci(PCI), parse_pci_verbose(VERBOSE))
        record = new_record('PRE')
        record.update(pci=parse_pci(PCI), pci_devices=devices,
                      commands={'pci': {'valid': True, 'evidence': 'pre_pci.txt'},
                                'pci_verbose': {'valid': True, 'evidence': 'pre_pci_verbose.txt'}},
                      check_summary={'pci': 'PASS', 'pci_verbose': 'PASS'}, status='PASS', finished='2026-10-01T10:00:01+08:00')
        devices_out, counts, evaluated, result = _pci_summary(record)
        self.assertEqual([d['bdf'] for d in devices_out], ['0002:02:00.0', '0002:21:00.0', '0004:01:00.0', '000c:01:00.0'])
        self.assertEqual(evaluated, 3)
        self.assertEqual(counts['N/A'], 1)
        self.assertEqual(result, 'PASS')
        self.assertEqual(devices['000c:01:00.0']['device_name'], 'KIOXIA Corporation Device')
        self.assertEqual(devices['0002:02:00.0']['link_result'], 'N/A')
        page = render_html(campaign([record]))
        self.assertIn('PCI / PCIe End Devices', page)
        self.assertIn('PCIe Endpoint Link Validation', page)
        self.assertIn('ASPEED Technology', page)
        self.assertIn('000c:01:00.0', page)
        self.assertIn('counts are PCI functions, not physical cards', page)
        self.assertIn('Expected:</strong> Not configured', page)
        self.assertNotIn('KIOXIA Corporation Device XD8', page)
        page_repeat = render_html(campaign([record]))
        self.assertEqual(page.count('PCI / PCIe End Devices'), page_repeat.count('PCI / PCIe End Devices'))

    def test_pci_group_accepts_another_project_shape_without_sample_defaults(self):
        base = parse_pci('000a:09:00.0 Ethernet controller [0200]: Acme Adapter [abcd:1234]\n')
        verbose = parse_pci_verbose('''000a:09:00.0 Ethernet controller
 Capabilities: [80] Express (v2) Endpoint
 LnkCap: Speed 8GT/s, Width x2
 LnkSta: Speed 8GT/s, Width x2
''')
        record = new_record('PRE')
        record.update(pci=base, pci_devices=merge_pci_devices(base, verbose),
                      commands={'pci': {'valid': True, 'evidence': 'pre_pci.txt'}, 'pci_verbose': {'valid': True, 'evidence': 'pre_pci_verbose.txt'}},
                      status='PASS', finished='2026-10-01T10:00:01+08:00')
        html = _render_pci_group(record)
        self.assertIn('000a:09:00.0', html)
        self.assertIn('Acme Adapter', html)
        self.assertNotIn('0002:02:00.0', html)
        self.assertIn('1 device item(s)', html)

    def test_link_unknown_and_all_na_never_become_pass(self):
        missing = parse_pci_verbose("""0000:01:00.0 Non-Volatile memory controller
 Capabilities: [80] Express (v2) Endpoint
 LnkCap: Speed 16GT/s, Width x4
""")
        self.assertEqual(missing['0000:01:00.0']['link_result'], 'FAIL')
        all_na = new_record('PRE')
        all_na.update(pci_devices={'0000:02:00.0': {'bdf': '0000:02:00.0', 'id': '1a03:2000', 'class_id': '0300', 'class_name': 'VGA', 'device_name': 'Display', 'link_result': 'N/A', 'link_reason': 'No link capability'}},
                      commands={'pci': {'valid': True, 'evidence': 'pre_pci.txt'}}, status='PASS', finished='2026-10-01T10:00:01+08:00')
        self.assertEqual(_pci_summary(all_na)[3], 'N/A')
        html = _render_pci_group(all_na)
        self.assertIn('N/A', html)
        self.assertNotIn('>PASS<', html)
        failed = new_record('PRE')
        failed.update(commands={'pci': {'valid': False, 'evidence': 'pre_pci.txt'}}, status='FAIL', finished='2026-10-01T10:00:01+08:00')
        failed_html = _render_pci_group(failed)
        self.assertIn('collection failed', failed_html)
        self.assertIn('FAIL', failed_html)

    def test_pcie_type_and_access_denied_are_not_guessed(self):
        rciep = parse_pci_verbose("""0000:01:00.0 Controller
 Capabilities: [80] Express (v2) Root Complex Integrated Endpoint
""")
        self.assertEqual(rciep['0000:01:00.0']['link_result'], 'N/A')
        denied = merge_pci_devices(parse_pci('0000:02:00.0 Ethernet controller [0200]: Adapter [1234:5678]\n'),
                                   parse_pci_verbose('0000:02:00.0 Ethernet controller\n Capabilities: <access denied>\n'))
        self.assertEqual(denied['0000:02:00.0']['link_result'], 'FAIL')
        unusable = parse_pci_verbose("""0000:03:00.0 Controller
 Capabilities: [80] Express (v2) Endpoint
 LnkSta: DLActive-
""")
        self.assertEqual(unusable['0000:03:00.0']['link_result'], 'FAIL')

    def test_start_and_loop_sel_have_distinct_semantics(self):
        start = new_record('START')
        start.update(status='PASS', finished='2026-10-01T10:00:02+08:00',
                     commands={'start_sel_clear': {'valid': True, 'state': 'RETURNED', 'code': 0,
                                                   'command': 'ipmitool sel clear', 'evidence': 'start/start_sel_clear.txt'}})
        start_html = record_html(start, 0)
        # START no longer clears SEL; clearing moved to PRE.
        self.assertIn('SEL is not cleared here', start_html)
        self.assertIn('runs in PRE', start_html)
        self.assertNotIn('No start_sel_clear record', start_html)
        self.assertNotIn('BMC SEL delta: MISSING', start_html)
        self.assertNotIn('OS boot changed', start_html)

        loop = new_record('LOOP 1')
        loop['loop'] = 1
        loop.update(status='PASS', finished='2026-10-01T10:00:03+08:00',
                    sel_before_meta={'phase': 'BEFORE_CYCLE', 'status': 'COLLECTED', 'valid': True, 'event_count': 2, 'evidence': 'loop0001/sel_before.txt'},
                    sel_post_meta={'phase': 'POST', 'status': 'COLLECTED', 'valid': True, 'event_count': 2, 'evidence': 'loop0001/sel.txt'},
                    sel_delta_meta={'phase': 'LOOP', 'status': 'COMPARED', 'valid': True, 'new_event_count': 0, 'evidence': 'loop0001/sel_delta.txt'},
                    sel_events=[], action=[{'command': 'power cycle', 'role': 'os', 'state': 'SENT', 'code': 0}],
                    recovery={'boot_changed': True, 'attempts': 3, 'old_boot_id': 'boot-a', 'new_boot_id': 'boot-b'})
        loop_html = record_html(loop, 0)
        self.assertIn('Cycle action and recovery', loop_html)
        self.assertIn('power cycle', loop_html)
        self.assertIn('boot-a', loop_html)
        self.assertIn('boot-b', loop_html)
        self.assertIn('Recovery attempts', loop_html)
        self.assertIn('Delta: 0 new events', loop_html)
        self.assertIn('Before-cycle SEL collection', loop_html)
        self.assertIn('POST SEL collection', loop_html)

        new_event = dict(loop)
        new_event['sel_events'] = ['1 | <new> & asserted']
        new_event['sel_delta_meta'] = dict(loop['sel_delta_meta'], new_event_count=1)
        new_html = _render_sel(new_event)
        self.assertIn('Delta: 1 new events', new_html)
        self.assertIn('REVIEW REQUIRED', new_html)
        self.assertIn('&lt;new&gt;', new_html)

        unavailable = dict(loop)
        unavailable['sel_before_meta'] = dict(loop['sel_before_meta'], valid=False, status='FAILED', event_count=None)
        unavailable['sel_delta_meta'] = dict(loop['sel_delta_meta'], valid=False, status='UNAVAILABLE', new_event_count=None, reason='before collection failed', evidence='')
        unavailable_html = _render_sel(unavailable)
        self.assertIn('Delta: UNAVAILABLE', unavailable_html)
        self.assertIn('Event count: --', unavailable_html)
        self.assertNotIn('>None<', unavailable_html)

        legacy = new_record('LOOP 2')
        legacy['loop'] = 2
        legacy.pop('sel_evidence_schema')
        legacy.update(sel_events=[], status='PASS', finished='2026-10-01T10:00:04+08:00')
        legacy_html = _render_sel(legacy)
        self.assertIn('NOT RETAINED — legacy run', legacy_html)
        self.assertNotIn('Delta: 0 new events', legacy_html)

    def test_findings_summary_counts_actual_record_and_escapes_raw(self):
        record = new_record('LOOP 5')
        record['loop'] = 5
        record.update(status='FAIL', finished='2026-10-01T10:00:05+08:00',
                      issues=[issue('A', '<sensor>', '<bad>', 'FAIL', snippet='<script>alert(1)</script>'),
                              issue('B', 'dmesg', 'warn 1', 'WARN'), issue('C', 'dmesg', 'warn 2', 'WARN'),
                              issue('D', 'dmesg', 'warn 3', 'WARN'), issue('E', 'dmesg', 'warn 4', 'WARN')])
        for item in record['issues']:
            item['classification'] = 'KNOWN'
        self.assertEqual(_finding_summary(record), '1 FAIL · 4 WARN · 5 KNOWN / 0 NEW')
        page = record_html(record, 0)
        self.assertIn('1 FAIL', page)
        self.assertIn('4 WARN', page)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', page)
        self.assertIn('&lt;sensor&gt;', page)
        self.assertNotIn('<script>alert(1)</script>', page)

    def test_issue_scope_lists_observed_phases_without_inventing_range(self):
        item = dict(node='tray1_n1', component='sensor', code='SENSOR_NONCRITICAL', detail='Repeated warning', severity='WARN', classification='KNOWN',
                    occurrences=[{'phase': 'LOOP 1', 'detail': 'a', 'snippet': '', 'evidence': 'loop0001/sensor.txt'},
                                 {'phase': 'LOOP 5', 'detail': 'b', 'snippet': '', 'evidence': 'loop0005/sensor.txt'}])
        html = issue_cards([item], {'tray1_n1': 0})
        self.assertIn('LOOP 1, LOOP 5', html)
        self.assertNotIn('Loops 1–5', html)

    def test_hardware_fail_carries_bf4_cause_without_duplicate_health_claim(self):
        record = new_record('PRE')
        record.update(status='FAIL', finished='2026-10-01T10:00:06+08:00',
                      check_summary={'hardware': 'FAIL', 'BF4': 'FAIL'},
                      hardware_checks={'BF4': 'FAIL'},
                      hardware_check_details={'BF4': {'values': {'actual': '0', 'exact': '1', 'pci_functions': '0'}, 'status': 'FAIL'}},
                      issues=[issue('BF4_MISSING', 'BF4', 'Expected at least 1; detected 0')])
        page = record_html(record, 0)
        self.assertIn('Cause: BF4 missing', page)
        self.assertIn('pci_functions=0', page)
        self.assertIn('BF4 validation', page)

    def test_nic_degraded_slot_is_not_reported_as_missing(self):
        # A NIC that is enumerated (holds its PCI slot) but whose MST device
        # type is not Vera must render as a degraded slot, never as a removed
        # card. lspci still shows the slot, so "missing" would be wrong. The
        # slot BDF is the upstream root port, so the summary must name the
        # downstream NIC and its MST device (甲+丙) rather than read as a
        # missing first-level bridge.
        record = new_record('PRE')
        record.update(status='FAIL', finished='2026-10-01T10:00:06+08:00',
                      check_summary={'hardware': 'FAIL', 'NIC': 'FAIL'},
                      hardware_checks={'NIC': 'FAIL'},
                      hardware_check_details={'NIC': {'values': {'actual': '21', 'minimum': '22'}, 'status': 'FAIL'}},
                      issues=[issue('NIC_DEGRADED', 'NIC',
                                    "root port 0002:00:00.0 -> downstream Vera NIC (MST device mt12184_pciconf0) "
                                    "degraded: DEVICE_TYPE='NA' (expected Vera); card present but not functional "
                                    "(degraded slot 0002:00:00.0). mst status row: NA /dev/mst/mt12184_pciconf0 0002:00:00.0 0")])
        page = record_html(record, 0)
        self.assertIn('degraded slot 0002:00:00.0', page)
        self.assertIn('root port -&gt; downstream Vera NIC', page)
        self.assertIn('mt12184_pciconf0', page)
        self.assertIn('DEVICE_TYPE=NA', page)
        self.assertIn('mst status row: NA /dev/mst/mt12184_pciconf0 0002:00:00.0 0', page)
        self.assertNotIn('missing slot 0002:00:00.0', page)

    def test_pci_and_sel_text_is_html_escaped(self):
        record = new_record('PRE')
        record.update(status='PASS', finished='2026-10-01T10:00:07+08:00',
                      pci_devices={'0000:01:00.0': {'bdf': '0000:01:00.0', 'id': '1234:5678', 'class_id': '0200',
                                                   'class_name': 'Ethernet', 'device_name': '<img src=x onerror=1>',
                                                   'link_result': 'UNKNOWN', 'link_reason': 'review'}},
                      commands={'pci': {'valid': True, 'evidence': 'pre_pci.txt'}})
        self.assertNotIn('<img src=x onerror=1>', _render_pci_group(record))
        loop = new_record('LOOP 1'); loop['loop'] = 1
        loop.update(sel_before_meta={'valid': True, 'status': 'COLLECTED', 'event_count': 0, 'evidence': 'before.txt'},
                    sel_post_meta={'valid': True, 'status': 'COLLECTED', 'event_count': 1, 'evidence': 'post.txt'},
                    sel_delta_meta={'valid': True, 'status': 'COMPARED', 'new_event_count': 1, 'evidence': 'delta.txt'},
                    sel_events=['1 | <script>alert(1)</script>'])
        sel_html = _render_sel(loop)
        self.assertNotIn('<script>alert(1)</script>', sel_html)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', sel_html)

    def test_declared_but_missing_new_evidence_is_distinct_from_legacy(self):
        record = new_record('LOOP 1'); record['loop'] = 1
        record.update(status='PASS', finished='2026-10-01T10:00:08+08:00',
                     sel_before_meta={'valid': True, 'status': 'COLLECTED', 'event_count': 0, 'evidence': 'loop0001/sel_before.txt'},
                     sel_post_meta={'valid': True, 'status': 'COLLECTED', 'event_count': 0, 'evidence': 'loop0001/sel.txt'},
                     sel_delta_meta={'valid': True, 'status': 'COMPARED', 'new_event_count': 0, 'evidence': 'loop0001/sel_delta.txt'},
                     missing_evidence=['loop0001/sel_before.txt'])
        html = _render_sel(record)
        self.assertIn('MISSING', html)
        self.assertNotIn('NOT RETAINED — legacy run', html)

    def test_pcie_hardware_fail_overrides_parser_pass_and_is_grouped_once(self):
        bdf = '0004:01:00.0'
        record = new_record('LOOP 1')
        record['loop'] = 1
        record.update(status='FAIL', finished='2026-10-01T10:00:09+08:00',
                      pci_devices={bdf: {'bdf': bdf, 'id': '1e0f:002e', 'class_id': '0108',
                                         'class_name': 'Non-Volatile memory controller',
                                         'device_name': 'KIOXIA NVMe', 'link_result': 'PASS',
                                         'link_reason': 'lspci reports usable link'}},
                      hardware_checks={f'PCIE_LINK/{bdf}': 'FAIL', f'PCIE_DOWNGRADE/{bdf}': 'FAIL'},
                      hardware_check_details={f'PCIE_LINK/{bdf}': {'raw': f'CHECK|PCIE_LINK|bdf={bdf}|lnksta=Speed unknown'},
                                              f'PCIE_DOWNGRADE/{bdf}': {'raw': f'CHECK|PCIE_DOWNGRADE|bdf={bdf}|lnksta=downgraded'}},
                      check_summary={f'PCIE_LINK/{bdf}': 'FAIL', f'PCIE_DOWNGRADE/{bdf}': 'FAIL'},
                      commands={'pci': {'valid': True, 'evidence': 'loop0001/pci.txt'},
                                'pci_verbose': {'valid': True, 'evidence': 'loop0001/pci_verbose.txt'}},
                      issues=[issue('PCIE_DOWNGRADE', bdf, 'LnkSta downgraded')])
        devices, counts, evaluated, result = _pci_summary(record)
        self.assertEqual(result, 'FAIL')
        self.assertEqual(counts['FAIL'], 1)
        self.assertEqual(evaluated, 1)
        self.assertEqual(devices[0]['_effective_link_result'], 'FAIL')
        group = _render_pci_group(record)
        self.assertIn('captures differ', group)
        self.assertIn('FAIL', group)
        summary = _render_summary_groups(record)
        self.assertNotIn(f'PCIE_LINK/{bdf}', summary)
        self.assertNotIn(f'PCIE_DOWNGRADE/{bdf}', summary)
        self.assertIn('PCIe End Devices', summary)
        self.assertIn('FAIL', summary)

    def test_new_loop_failure_before_post_is_not_called_legacy(self):
        loop = new_record('LOOP 24')
        loop['loop'] = 24
        loop.update(status='FAIL', finished='2026-10-01T10:00:10+08:00',
                    sel_before_meta={'phase': 'BEFORE_CYCLE', 'status': 'COLLECTED', 'valid': True,
                                     'event_count': 3, 'evidence': 'loop0024/sel_before.txt'},
                    commands={'sel_before': {'valid': True, 'state': 'RETURNED', 'evidence': 'loop0024/sel_before.txt'},
                              'failure_sel': {'valid': False, 'state': 'RESPONSE_LOST', 'evidence': 'loop0024/failure_sel.txt'}},
                    issues=[issue('BOOT_TIMEOUT', 'recovery', 'Boot recovery timed out')])
        html = _render_sel(loop)
        self.assertIn('Before-cycle SEL collection', html)
        self.assertIn('Failure-path SEL collection', html)
        self.assertIn('Delta: UNAVAILABLE', html)
        self.assertNotIn('NOT RETAINED — legacy run', html)
        self.assertIn('POST SEL collection', html)


if __name__ == '__main__':
    unittest.main()
