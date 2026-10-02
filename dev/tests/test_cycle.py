"""Offline regressions. No SSH, network, apt, IPMI or hardware access."""
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from cycle_core import *
from cycle_engine import CAPTURES, NodeSession, new_record
from cycle_report import render_html, rebuild, status
from cycle_runtime import EndpointLocks, request_stop
from cycle_transport import Command, IdentityUnsafe
from neutrino_cycle import BASE, Console, campaign, main

PCI = '0000:01:00.0 Ethernet controller [0200]: Example [1234:5678]\n0001:01:00.0 PCI bridge [0604]: Fabric [10de:2f95]\n'
SENSORS = 'Temp | 30 | degrees C | ok | na\nFan | 12000 | RPM | ok | na\n'

def target(node='n1', tray='tray1', offset=0):
    return Target(tray, node, f'192.0.2.{1+offset}', f'192.0.2.{2+offset}', f'bmc-{node}', f'os-{node}')

class FakeTransport:
    def __init__(self, credentials, known_hosts):
        self.known_hosts = Path(known_hosts)
        self.boots = {}
        self.calls = []
        self.uploaded = {}
        self.mismatch = False
        self.empty_baseline = False
        self.hardware_failure = True
        self.pci_drift = False
        self.sensor_drop = False
        self.sensor_reads = 0
        self.response_lost = False
        self.no_recovery = False
        self.fail_command = False
        self.power_off = False
        self.on_action = None
        self.package_missing = False

    def local_dependencies(self):
        return Command(0, 'available')

    def upload(self, target, data, remote):
        self.uploaded[target.key] = data

    def action(self, t):
        if not self.no_recovery and not self.fail_command:
            self.boots[t.key] = self.boots.get(t.key, 0) + 1
        if self.on_action:
            self.on_action()
        return Command(1, 'rejected') if self.fail_command else Command(255, 'disconnected', 'RESPONSE_LOST') if self.response_lost else Command(0, 'accepted')

    def ssh(self, t, role, cmd, timeout=60, sudo=False):
        self.calls.append((t.key, role, cmd))
        if "printf 'HOSTNAME='" in cmd:
            name = 'wrong-host' if self.mismatch else getattr(t, role + '_hostname')
            boot = f'00000000-0000-0000-0000-{self.boots.get(t.key, 0):012d}'
            return Command(0, f'HOSTNAME={name}\nBOOT_ID={boot}\n')
        if cmd.startswith('ipmitool sel '):
            return self.oob(t, cmd.removeprefix('ipmitool '), timeout)
        if cmd.startswith('sha256sum '):
            return Command(0, digest(self.uploaded[t.key]) + ' file')
        if cmd == 'id -u':
            return Command(0, '0')
        if 'apt-get install' in cmd:
            self.package_missing = False
            return Command(0, 'installed')
        if 'MISSING=' in cmd:
            return Command(0, 'MISSING=lspci\n' if self.package_missing else '')
        if cmd in {'reboot', 'ipmitool power cycle', '/usr/bin/stbypowerctrl.sh aux_cycle'}:
            return self.action(t)
        if cmd == 'lspci -Dnn':
            return Command(0, '' if self.empty_baseline else PCI.splitlines()[0] if self.pci_drift and self.boots.get(t.key) == 1 else PCI)
        if (cmd.startswith('bash ') or cmd.startswith('MEMORY_MIN_RATIO=')):
            return Command(1, 'ISSUE|BF4_MISSING|BF4|Expected at least 1; detected 0\nRESULT|FAIL\n') if self.hardware_failure else Command(0, 'RESULT|PASS\n')
        if cmd == '/usr/bin/powerctrl.sh power_status':
            return Command(0, 'Host: Running\nChassis Power: On')
        if cmd in {value[0] for value in CAPTURES.values()} | {'dmesg -c', 'command -v mst'}:
            return Command(0, 'available\n')
        if cmd.startswith('test -f ') or cmd.startswith('rm -f '):
            return Command(0, '')
        return Command(127, 'Unsupported fake SSH command: ' + cmd)

    def oob(self, t, cmd, timeout=30):
        self.calls.append((t.key, 'oob', cmd))
        if cmd == 'sensor list':
            self.sensor_reads += 1
            text = SENSORS.splitlines()[0] if self.sensor_drop and self.sensor_reads == 2 else SENSORS
            return Command(0, text)
        if cmd == 'power soft':
            self.power_off = True
            return Command(0, 'soft sent')
        if cmd == 'power on':
            self.power_off = False
            return self.action(t)
        if cmd in {'power cycle', 'power reset'}:
            return self.action(t)
        if cmd == 'power status':
            return Command(0, 'Chassis Power is ' + ('off' if self.power_off else 'on'))
        if cmd == 'sel list':
            return Command(0, '1 | 09/29/2026 | 10:00:00 | System boot | Asserted\n')
        if cmd in {'mc info', 'sel clear'}:
            return Command(0, 'OK')
        return Command(127, 'Unsupported fake OOB command: ' + cmd)

    # --- Redfish fake -----------------------------------------------------
    # A merged-style BMC: EventLog exists, no separate SEL service.
    redfish_eventlog = [{"Id": "1", "Severity": "OK", "Created": "2000-01-03T04:44:02Z",
                         "Message": "xyz.openbmc_project.Logging.Cleared"}]
    redfish_sel_present = False
    redfish_fail = False

    def redfish_login(self, target, timeout=20):
        if self.redfish_fail:
            raise RuntimeError('redfish login failed (fake)')
        return 'FAKETOKEN'

    def redfish_get(self, target, path, token, timeout=30):
        self.calls.append((target.key, 'redfish', path))
        if self.redfish_fail:
            return Command(255, 'unreachable', 'NOT_ISSUED')
        if path == '/redfish/v1/Systems':
            return Command(0, json.dumps({"Members": [{"@odata.id": "/redfish/v1/Systems/System_0"}]}))
        if path == '/redfish/v1/Systems/System_0/LogServices':
            members = [{"@odata.id": "/redfish/v1/Systems/System_0/LogServices/EventLog"}]
            if self.redfish_sel_present:
                members.append({"@odata.id": "/redfish/v1/Systems/System_0/LogServices/SEL"})
            return Command(0, json.dumps({"Members": members}))
        if path.endswith('/EventLog/Entries'):
            return Command(0, json.dumps({"Members": self.redfish_eventlog}))
        if path.endswith('/SEL/Entries'):
            return Command(0, json.dumps({"Members": []}))
        return Command(127, 'Unsupported fake Redfish path: ' + path)

    def redfish_clear(self, target, path, token, timeout=30):
        self.calls.append((target.key, 'redfish-clear', path))
        return Command(0, 'OK')

class PureTests(unittest.TestCase):
    def test_truncated_sensor_row_cannot_disappear_from_pre(self):
        rows=parse_sensors(SENSORS+'Temp_CPU2 | 90 | degrees C\n')
        self.assertEqual(len(rows),3)
        self.assertEqual(health(sensor_issues(rows)),'FAIL')
        self.assertTrue(any(i['component']=='Temp_CPU2' for i in sensor_issues(rows)))

    def test_unnamed_and_short_sensor_rows_fail(self):
        for text in (' | 30 | degrees C | ok', 'Temp | 30', 'Temp | 30 | degrees C'):
            with self.subTest(text=text):
                items=sensor_issues(parse_sensors(SENSORS+text))
                self.assertEqual(health(items),'FAIL')
                self.assertIn('SENSOR_MALFORMED',[item['code'] for item in items])

    def test_pipeless_diagnostic_line_is_malformed_but_blank_is_ignored(self):
        rows=parse_sensors('Temp | 30 | C | ok\nError: Unable to establish IPMI v2 / RMCP+ session\n')
        self.assertEqual(len(rows),2)
        items=sensor_issues(rows)
        self.assertEqual(health(items),'FAIL')
        self.assertIn('SENSOR_MALFORMED',[item['code'] for item in items])
        self.assertEqual(health(sensor_issues(parse_sensors('Temp | 30 | C | ok\n\n   \n'))),'PASS')

    def test_aggregation_classifies_by_pre_baseline(self):
        # An issue present in PRE is KNOWN in the report even if it recurs in a
        # loop; an issue absent from PRE is NEW. PRE is the baseline by
        # definition, so the (code, component) pair is what decides.
        pre = new_record('PRE')
        loop1 = new_record('LOOP 1')
        pre['issues'] = [issue('BF4_MISSING', 'BF4', 'missing in pre', 'FAIL')]
        loop1['issues'] = [
            issue('BF4_MISSING', 'BF4', 'still missing', 'FAIL'),        # in PRE -> KNOWN
            issue('DMESG_PCIE', '0001:02:00.0', 'AER surfaced', 'FAIL'),  # not in PRE -> NEW
        ]
        data = {'nodes': [{'key': 'tray_n1', 'pre': pre, 'loops': [loop1]}]}
        merged = aggregate_issues(data)
        by_code = {m['code']: m for m in merged}
        self.assertEqual(by_code['BF4_MISSING']['classification'], 'KNOWN')
        self.assertEqual(by_code['DMESG_PCIE']['classification'], 'NEW')
        self.assertEqual(by_code['DMESG_PCIE']['known_reason'], '')
        self.assertEqual(by_code['BF4_MISSING']['known_reason'], 'Present in PRE baseline')
        self.assertEqual(len(by_code['BF4_MISSING']['occurrences']), 2)

    def test_duplicate_sensor_cannot_hide_fault(self):
        rows = parse_sensors('Temp | 90 | C | cr\nTemp | 30 | C | ok\n')
        items = sensor_issues(rows)
        self.assertEqual(health(items), 'FAIL')
        self.assertIn('SENSOR_DUPLICATE', [i['code'] for i in items])

    def test_sensor_statuses(self):
        for state in ('cr','critical','nr','non-recoverable','ns','na','no reading','ucr','lcr','lnr','unr'):
            with self.subTest(state=state):
                self.assertEqual(health(sensor_issues(parse_sensors(f'Temp | 30 | C | {state}'))), 'FAIL')
        self.assertEqual(health(sensor_issues(parse_sensors('Temp | 30 | C | nc'))), 'WARN')

    def test_discrete_hex_status_is_normal(self):
        rows = parse_sensors(
            'NVMeE1SSSD0STS0 | 0x0 | discrete | 0x0100 | na | na\n'
            'NVMeE1SSSD1STS0 | 0x0 | discrete | 0x0000 | na | na\n'
        )
        self.assertEqual(sensor_issues(rows), [])
        self.assertEqual(health(sensor_issues(rows)), 'PASS')
        self.assertEqual(
            health(sensor_issues(parse_sensors('Temp | 0x0 | degrees C | 0x0100'))),
            'FAIL',
        )

    def test_known_vera_no_reading_rows_are_ignored_but_generic_na_fails(self):
        rows = parse_sensors(
            'PrMo0CP1CorUti11 | na | discrete | na | na\n'
            'PrMo0CP1CorUti24 | na | percent | na | na\n'
        )
        self.assertEqual(sensor_issues(rows), [])
        self.assertEqual(
            health(sensor_issues(parse_sensors('Fan | na | percent | na'))),
            'FAIL',
        )
        # Garbled names must never be whitelisted, with or without a unit.
        self.assertEqual(
            health(sensor_issues(parse_sensors('\ufffd\ufffd\ufffd\ufffd | na | percent | na'))),
            'FAIL',
        )
        self.assertEqual(
            health(sensor_issues(parse_sensors('\ufffd\ufffd\ufffd\ufffd | na |  | na'))),
            'FAIL',
        )

    def test_sensor_missing_and_reread(self):
        pre = parse_sensors(SENSORS)
        initial = pre[:1]
        self.assertEqual(health(compare_sensors(pre, initial, pre)), 'WARN')
        self.assertEqual(health(compare_sensors(pre, initial, initial)), 'FAIL')
        self.assertEqual(health(compare_sensors(pre, initial, pre[1:])), 'FAIL')

    def test_pci_domains_and_ids(self):
        parsed = parse_pci(PCI)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed['0001:01:00.0']['id'], '10de:2f95')
        self.assertEqual(len(pci_issues(parsed, parse_pci(PCI.replace('1234:5678','1234:9999')))), 1)

    def test_pci_drift_quotes_pre_and_post_lines(self):
        before = parse_pci('0001:01:00.0 PCI bridge [0604]: Fabric [10de:2f95]\n')
        after = parse_pci('0001:01:00.0 PCI bridge [0604]: Fabric [10de:9999]\n')
        item = pci_issues(before, after)[0]
        self.assertIn('PRE ', item['snippet'])
        self.assertIn('10de:2f95', item['snippet'])
        self.assertIn('POST', item['snippet'])
        self.assertIn('10de:9999', item['snippet'])

    def test_dmesg_issue_points_at_line_number(self):
        text = 'first line\nAER: Uncorrected (Fatal) error\nanother\n'
        item = dmesg_issues(text)[0]
        self.assertEqual(item['code'], 'DMESG_PCIE')
        self.assertIn('dmesg line 2:', item['snippet'])
        self.assertIn('Uncorrected', item['snippet'])

    def test_apei_info_block_is_benign_and_collapses(self):
        # Real L105-21R_n1 loop0054 shape: one GHES event, severity info,
        # spread across many lines (severity/type/section/hex dump).
        text = (
            '[ 10.289492] {1}[Hardware Error]: Hardware error from APEI Generic Hardware Error Source: 8194\n'
            '[ 10.295257] {1}[Hardware Error]: event severity: info\n'
            '[ 10.300241] {1}[Hardware Error]:  Error 0, type: info\n'
            '[ 10.305226] {1}[Hardware Error]:   section type: unknown, 9068e568-...\n'
            '[ 10.313731] {1}[Hardware Error]:   section length: 0xe0\n'
            '[ 10.318888] {1}[Hardware Error]:   00000000: 00000101 00000000 00000000 00000000\n'
            '[ 10.327737] {1}[Hardware Error]:   00000010: 4c504343 43555845 00000046 00000000\n'
            'plain unrelated line\n'
        )
        self.assertEqual(dmesg_issues(text), [])

    def test_apei_severe_block_reports_once(self):
        text = (
            '[ 10.289492] {1}[Hardware Error]: Hardware error from APEI Generic Hardware Error Source: 8194\n'
            '[ 10.295257] {1}[Hardware Error]: event severity: corrected\n'
            '[ 10.300241] {1}[Hardware Error]:  Error 0, type: corrected\n'
            '[ 10.318888] {1}[Hardware Error]:   00000000: 00000101 00000000 00000000 00000000\n'
            '[ 10.327737] {1}[Hardware Error]:   00000010: 4c504343 43555845 00000046 00000000\n'
        )
        items = dmesg_issues(text)
        self.assertEqual(len(items), 1)
        self.assertIn('corrected', items[0]['detail'])
        self.assertIn('8194', items[0]['detail'])

    def test_missing_sensor_quotes_baseline_row(self):
        baseline = parse_sensors(SENSORS)
        current = parse_sensors('Temp | 30 | degrees C | ok | na\n')
        item = next(i for i in compare_sensors(baseline, current, current) if i['code'] == 'SENSOR_MISSING')
        self.assertIn('Fan', item['snippet'])
        self.assertIn('line 2:', item['snippet'])

    def test_downgrade_issue_carries_lnksta(self):
        text = ('CHECK|PCIE_DOWNGRADE|bdf=0000:01:00.0|lnksta=Speed 32GT/s, Width x2 (downgraded)\n'
                'ISSUE|PCIE_DOWNGRADE|0000:01:00.0|NVMe: LnkSta: Speed 32GT/s, Width x2 (downgraded)\n'
                'RESULT|FAIL\n')
        item = next(i for i in config_issues(text, 1) if i['code'] == 'PCIE_DOWNGRADE')
        self.assertIn('lnksta=Speed 32GT/s, Width x2', item['snippet'])

    def test_structural_issues_have_no_snippet(self):
        # A script that never answered has no evidence row to point at.
        item = config_issues('RESULT|FAIL\n', 1)[0]
        self.assertEqual(item['snippet'], '')

    def test_identical_duplicate_sensor_stays_visible(self):
        items = sensor_issues(parse_sensors(SENSORS + SENSORS.splitlines()[0] + '\n'))
        self.assertEqual(health(items), 'WARN')
        self.assertEqual(sum(i['code'] == 'SENSOR_DUPLICATE' for i in items), 1)

    def test_raw_bridge_downgrade_not_an_endpoint_issue(self):
        text = '0000:01:00.0 PCI bridge\n Capabilities: Express Root Port\n LnkSta: Width x4 (downgraded)\nRESULT|PASS'
        self.assertEqual(config_issues(text, 0), [])

    def test_pcie_downgrade_is_always_a_failure(self):
        text = (
            '[Evidence] PCIe-links\n'
            '0004:01:00.0 Non-Volatile memory controller: KIOXIA NVMe\n'
            '\tCapabilities: [80] Express (v2) Endpoint\n'
            '\tLnkSta: Speed 32GT/s, Width x2 (downgraded)\n'
            'RESULT|PASS\n'
        )
        items = config_issues(text, 0)
        self.assertEqual(health(items), 'FAIL')
        self.assertIn('PCIE_DOWNGRADE', [item['code'] for item in items])

    def test_empty_config_is_not_pass(self):
        self.assertEqual(health(config_issues('', 0)), 'FAIL')
        self.assertEqual(health(config_issues('RESULT|FAIL', 0)), 'FAIL')
        self.assertEqual(health(config_issues('RESULT|PASS', 0)), 'PASS')

    def test_config_issue_carries_check_measurement_as_snippet(self):
        # Missing hardware has no offending row; the CHECK measurement is the
        # evidence the issue card shows.
        text = ('CHECK|BF4|actual=0|minimum=1|mst_bluefield=0|pci_bluefield=0\n'
                'ISSUE|BF4_MISSING|BF4|Expected at least 1; detected 0\n'
                'RESULT|FAIL\n')
        item = next(i for i in config_issues(text, 1) if i['code'] == 'BF4_MISSING')
        self.assertIn('actual=0', item['snippet'])
        self.assertIn('expected 1', item['snippet'])

    def test_config_issue_without_check_has_empty_snippet(self):
        text = 'ISSUE|BF4_MISSING|BF4|Expected at least 1; detected 0\nRESULT|FAIL\n'
        item = next(i for i in config_issues(text, 1) if i['code'] == 'BF4_MISSING')
        self.assertEqual(item['snippet'], '')

    def test_classify_against_pre_baseline(self):
        # A finding present in PRE is KNOWN (pre-existing); one absent is NEW.
        pre = [issue('BF4_MISSING', 'BF4', 'missing')]
        pre_keys = {(i['code'], i['component']) for i in pre}
        items = classify_against_pre([
            issue('BF4_MISSING', 'BF4', 'still missing', 'FAIL'),
            issue('DMESG_PCIE', '0001:02:00.0', 'uncorrected AER', 'FAIL'),
        ], pre_keys)
        self.assertEqual(items[0]['classification'], 'KNOWN')
        self.assertEqual(items[1]['classification'], 'NEW')
        # A PRE record classifies against an empty baseline -> everything NEW.
        pre_only = classify_against_pre([issue('BF4_MISSING', 'BF4', 'missing')], set())
        self.assertEqual(pre_only[0]['classification'], 'NEW')
        self.assertEqual(health(items), 'FAIL')

    def test_sel_reused_id_with_new_timestamp(self):
        old = '1 | yesterday | boot\n'
        current = old + '1 | today | boot\n'
        self.assertEqual(sel_delta(old,current), '1 | today | boot\n')

    def test_dmesg_specific_not_every_error_word(self):
        self.assertFalse(dmesg_issues('AER: enabled error reporting\n0 errors'))
        self.assertEqual(health(dmesg_issues('AER: Uncorrected (Fatal) error received')), 'FAIL')

    def test_inventory_selection_duplicates(self):
        nodes = [target(), target(tray='tray2',offset=2)]
        with self.assertRaisesRegex(ValueError,'ambiguous'):
            select_targets(nodes,['n1'])
        with self.assertRaisesRegex(ValueError,'Duplicate'):
            select_targets(nodes,['tray1/n1','tray1/n1'])
        with self.assertRaises(ValueError):
            select_targets(nodes,['n99'])
        self.assertEqual(select_targets(nodes,['tray2/n1']), nodes[1:])
        self.assertFalse(inventory_blocks(nodes))
        self.assertEqual(len(inventory_blocks([target(),target('n2')])),2)

    def test_csv_named_columns_and_missing_hostnames(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'inventory.csv'
            path.write_text('os_hostname,node,os_ip,tray,bmc_hostname,bmc_ip\nos,n1,192.0.2.2,tray,bmc,192.0.2.1\n')
            self.assertFalse(inventory_blocks(load_inventory(path)))
        shipped=load_inventory(BASE/'cycle_inventory_neutrino.csv')
        self.assertTrue(shipped)
        # n0 is a placeholder for hardware that is not provisioned yet, so it
        # stays blocked until its hostnames are filled in; every other row runs.
        blocked=inventory_blocks(shipped)
        self.assertEqual(sorted(t.node for t in shipped if t.key not in blocked),['n1','n2','n3'])

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.options = SimpleNamespace(project='neutrino',cycle_mode='power_cycle',channel='inband',
                                       boot_timeout=.03,poll_interval=.001,loops=2,hours=0,cycle=True,
                                       config_script=BASE/'neutrino_config.sh',issue_policy=BASE/'issue_policy.md',output=self.root/'output',
                                       sensor_retry_delay=0)
        self.fake = FakeTransport({}, self.root/'ssh')
        self.session = NodeSession(target(),self.fake,self.root,'test',b'script',digest(b'script'),self.options,
                                   parse_policy(self.options.issue_policy.read_text()))

    def tearDown(self):
        self.temp.cleanup()

    def ready(self):
        self.session.precheck()
        self.assertFalse(self.session.node['blocked'])
        self.session.start()

    def test_sel_uses_before_snapshot_not_previous_post(self):
        self.ready()
        old = '1 | 09/30/2026 | 10:00:00 | Old event | Asserted\n'
        between = '2 | 09/30/2026 | 10:05:00 | Between loops | Asserted\n'
        fresh = '1 | 09/30/2026 | 10:10:00 | Boot event | Asserted\n'
        replies = iter([old + between, old + between + fresh])
        original = self.fake.oob
        def oob(t, cmd, timeout=30):
            return Command(0, next(replies)) if cmd == 'sel list' else original(t, cmd, timeout)
        self.fake.oob = oob
        record = self.session.one_loop(1)
        self.assertEqual(record['sel_events'], [fresh.strip()])
        self.assertNotIn('sel_before', record)
        self.assertTrue((self.root/'tray1_n1'/'pre_sel.txt').exists())
        self.assertTrue((self.root/'tray1_n1'/'loop0001'/'sel_before.txt').exists())
        self.assertTrue((self.root/'tray1_n1'/'loop0001'/'sel.txt').exists())
        self.assertTrue((self.root/'tray1_n1'/'loop0001'/'sel_delta.txt').exists())
        self.assertTrue(self.session.node['pre']['sel_collection']['valid'])
        self.assertEqual(self.session.node['pre']['commands']['pre_sel_clear']['command'], 'ipmitool sel clear')
        self.assertEqual(record['sel_before_meta']['phase'], 'BEFORE_CYCLE')
        self.assertEqual(record['sel_post_meta']['phase'], 'POST')
        self.assertGreaterEqual(record['duration_seconds'], 0)

    def test_sel_channel_and_clear_once(self):
        for channel in ('inband', 'outband'):
            with self.subTest(channel=channel):
                self.options.channel = channel
                self.fake.calls.clear()
                self.ready()
                self.session.one_loop(1)
                self.session.one_loop(2)
                # Fake SSH delegates IPMI to its response helper; inspect SSH
                # calls to establish the requested transport independently.
                os_calls = [cmd for _, role, cmd in self.fake.calls if role == 'os' and cmd.startswith('ipmitool sel')]
                self.assertEqual(bool(os_calls), channel == 'inband')
                clear_calls = [cmd for _, role, cmd in self.fake.calls if role == 'oob' and cmd == 'sel clear']
                self.assertEqual(len(clear_calls), 1)

    def test_pre_duration_does_not_include_campaign_log_clearing(self):
        self.session.precheck()
        before = self.session.node['pre']['duration_seconds']
        self.session.start()
        self.assertEqual(self.session.node['pre']['duration_seconds'], before)

    def test_unrecognized_sel_never_looks_like_zero_events(self):
        self.ready()
        original = self.fake.oob
        self.fake.oob = lambda t, cmd, timeout=30: Command(0, '') if cmd == 'sel list' else original(t, cmd, timeout)
        record = self.session.one_loop(1)
        self.assertIsNone(record['sel_events'])
        self.assertEqual(record['sel_status'], 'COLLECTION FAILED')
        self.assertIn('SEL_FORMAT_ERROR', [i['code'] for i in record['issues']])

    def test_original_pre_and_all_loops_despite_failure(self):
        self.fake.pci_drift = True
        self.ready()
        one = self.session.one_loop(1)
        two = self.session.one_loop(2)
        self.assertIn('PCI_DRIFT',[i['code'] for i in one['issues']])
        self.assertNotIn('PCI_DRIFT',[i['code'] for i in two['issues']])
        self.assertEqual(two['status'],'FAIL')
        self.assertEqual(self.session.node['completed'],2)
        self.assertEqual(sum(cmd=='sel clear' for _,_,cmd in self.fake.calls),1)
        self.assertEqual(sum(cmd=='dmesg -c' for _,_,cmd in self.fake.calls),3)
        self.assertTrue((self.root/'tray1_n1'/'pre_pci.txt').exists())
        self.assertFalse((self.root/'tray1_n1'/'pre').exists())
        self.assertTrue((self.root/'tray1_n1'/'loop0002'/'sel.txt').exists())
        loop_files = {path.name for path in (self.root/'tray1_n1'/'loop0002').iterdir()}
        self.assertFalse(any(name.startswith('boot_poll') for name in loop_files))
        self.assertFalse(any(name.endswith('_before_cycle.txt') or name.endswith('_after_cycle.txt') for name in loop_files))
        self.assertFalse(any(name.startswith('post_') for name in loop_files))

    def test_wrong_hostname_prevents_any_mutation(self):
        self.fake.mismatch = True
        self.session.precheck()
        self.assertTrue(self.session.node['blocked'])
        self.assertFalse(self.fake.uploaded)
        self.assertFalse(any('apt-get' in cmd or cmd=='dmesg -c' for _,_,cmd in self.fake.calls))

    def test_post_hostname_mismatch_prevents_another_cycle(self):
        self.ready()
        self.fake.on_action=lambda: setattr(self.fake,'mismatch',True)
        result=self.session.one_loop(1)
        self.assertFalse(self.session.node['active'])
        self.assertIn('IDENTITY_UNSAFE',[i['code'] for i in result['issues']])

    def test_bmc_transient_after_os_boot_retries(self):
        self.options.boot_timeout=.5
        self.ready()
        original=self.fake.ssh
        failed=[]
        def ssh(t,role,cmd,timeout=60,sudo=False):
            if role=='bmc' and self.fake.boots.get(t.key,0)>0 and not failed:
                failed.append(True)
                return Command(255,'connection refused','NOT_ISSUED')
            return original(t,role,cmd,timeout,sudo)
        self.fake.ssh=ssh
        result=self.session.one_loop(1)
        self.assertTrue(self.session.node['active'])
        self.assertTrue(result['recovery']['boot_changed'])
        self.assertGreaterEqual(result['recovery']['attempts'],2)

    def test_sel_exit_zero_error_still_fails(self):
        self.ready()
        original=self.fake.oob
        def oob(t,cmd,timeout=30):
            if cmd=='sel list':
                return Command(0,'SEL has no entries\nGet SEL Info command failed')
            return original(t,cmd,timeout)
        self.fake.oob=oob
        result=self.session.one_loop(1)
        self.assertIn('IPMI_REPORTED_ERROR',[i['code'] for i in result['issues']])

    def test_pre_sel_error_is_never_cleared(self):
        original=self.fake.oob
        def oob(t,cmd,timeout=30):
            if cmd=='sel list':
                return Command(0,'SEL has no entries\nGet SEL Info command failed')
            return original(t,cmd,timeout)
        self.fake.oob=oob
        self.ready()
        self.assertFalse(any(cmd=='sel clear' for _,_,cmd in self.fake.calls))
        self.assertIn('CLEAR_SKIPPED',[i['code'] for i in self.session.node['pre']['issues']])

    def test_all_cycle_modes_and_channels(self):
        self.ready()
        for mode in ('reboot','power_cycle','aux_cycle'):
            for channel in ('inband','outband'):
                self.options.cycle_mode,self.options.channel=mode,channel
                record=self.session.one_loop(len(self.session.node['loops'])+1)
                self.assertTrue(record['recovery']['boot_changed'],(mode,channel))
                self.assertTrue(record['post_complete'])

    def test_partial_baseline_is_blocked(self):
        self.fake.empty_baseline = True
        self.session.precheck()
        self.assertTrue(self.session.node['blocked'])

    def test_malformed_sensor_table_is_fail_but_operator_can_review_it(self):
        original=self.fake.oob
        for text in [('Temp | 30 | degrees C'),(SENSORS+'Temp_CPU2 | 90 | degrees C')]:
            def oob(t,cmd,timeout=30):
                return Command(0,text) if cmd=='sensor list' else original(t,cmd,timeout)
            self.fake.oob=oob
            session=NodeSession(target(),self.fake,self.root,'test',b'script',digest(b'script'),self.options,[])
            session.precheck()
            self.assertFalse(session.node['blocked'])
            self.assertEqual(session.node['pre']['status'],'FAIL')
            self.assertIn('SENSOR_MALFORMED',[i['code'] for i in session.node['pre']['issues']])

    def test_pre_sensor_transport_failure_retries_once(self):
        original = self.fake.oob
        reads = {'count': 0}
        def oob(t, cmd, timeout=30):
            if cmd == 'sensor list':
                reads['count'] += 1
                if reads['count'] == 1:
                    return Command(124, 'timeout', 'RESPONSE_LOST')
            return original(t, cmd, timeout)
        self.fake.oob = oob
        self.options.sensor_retry_delay = 10
        with patch('cycle_engine.time.sleep') as wait:
            self.session.precheck()
        record = self.session.node['pre']
        self.assertEqual(reads['count'], 2)
        wait.assert_called_once_with(10)
        self.assertTrue(record['commands']['sensor_retry']['valid'])
        self.assertTrue((self.root/'tray1_n1'/'pre_sensor_retry.txt').exists())
        self.assertIn('COLLECTION_FAILED', [item['code'] for item in record['issues']])
        self.assertEqual(len(record['sensors']), 2)

    def test_failed_dmesg_clear_still_attempts_sel_without_key_error(self):
        original=self.fake.ssh
        def ssh(t,role,cmd,timeout=60,sudo=False):
            return Command(1,'permission denied') if cmd=='dmesg -c' else original(t,role,cmd,timeout,sudo)
        self.fake.ssh=ssh
        self.session.precheck()
        # Clean-start clearing lives in PRE now: a failed dmesg clear must not
        # stop SEL from being cleared, and the run still reaches a usable PRE.
        self.assertFalse(self.session.node['pre']['commands']['pre_dmesg_clear']['valid'])
        self.assertTrue(self.session.node['pre']['commands']['pre_sel_clear']['valid'])
        self.assertEqual(sum(cmd=='sel clear' for _,_,cmd in self.fake.calls),1)
        self.assertFalse(self.session.node['blocked'])

    def test_dispatch_not_issued_and_exception_paths(self):
        record=self.session.node['pre']
        with patch.object(self.fake,'ssh',return_value=Command(255,'offline','NOT_ISSUED')):
            self.assertEqual(self.session.dispatch(record,'cycle_test','os','reboot'),'NOT_ISSUED')
        with patch.object(self.fake,'ssh',side_effect=ConnectionError('connection failed')):
            with self.assertRaisesRegex(ConnectionError,'connection failed'):
                self.session.dispatch(record,'cycle_unreturned','os','reboot')
        self.assertNotIn('cycle_unreturned',record['commands'])

    def test_missing_sensor_reread_and_preserved_warning(self):
        self.fake.sensor_drop = True
        self.ready()
        self.options.sensor_retry_delay = 10
        with patch('cycle_engine.time.sleep') as wait:
            result = self.session.one_loop(1)
        self.assertIn('SENSOR_RECOVERED',[i['code'] for i in result['issues']])
        self.assertTrue((self.root/'tray1_n1'/'loop0001'/'sensor_confirm.txt').exists())
        wait.assert_any_call(10)

    def test_sensor_transport_failure_is_not_missing_hardware(self):
        self.ready()
        original=self.fake.oob
        def oob(t,cmd,timeout=30):
            if cmd=='sensor list':
                return Command(124,'timeout','RESPONSE_LOST')
            return original(t,cmd,timeout)
        self.fake.oob=oob
        result=self.session.one_loop(1)
        codes=[i['code'] for i in result['issues']]
        self.assertIn('COLLECTION_FAILED',codes)
        self.assertNotIn('SENSOR_MISSING',codes)

    def test_lost_response_is_reconciled_not_reissued(self):
        self.fake.response_lost = True
        self.ready()
        result = self.session.one_loop(1)
        self.assertEqual(result['action'][0]['state'],'RECONCILED')
        self.assertEqual(sum(cmd=='ipmitool power cycle' for _,_,cmd in self.fake.calls),1)

    def test_timeout_halts_target(self):
        self.fake.no_recovery = True
        self.ready()
        result = self.session.one_loop(1)
        self.assertFalse(self.session.node['active'])
        self.assertIn('BOOT_TIMEOUT',[i['code'] for i in result['issues']])

    def test_definite_command_failure_gets_post_and_can_continue(self):
        self.fake.fail_command = True
        self.ready()
        result = self.session.one_loop(1)
        self.assertTrue(self.session.node['active'])
        self.assertTrue(result['post_complete'])
        self.assertEqual(result['action'][0]['state'],'COMMAND_FAILED')

    def test_outband_reboot_uses_power_reset(self):
        self.options.cycle_mode='reboot'
        self.options.channel='outband'
        self.ready()
        result=self.session.one_loop(1)
        self.assertEqual([a['command'] for a in result['action']],['power reset'])

    def test_dependencies_installed_before_full_pre(self):
        self.fake.package_missing = True
        self.ready()
        commands = [cmd for _,_,cmd in self.fake.calls]
        self.assertLess(next(i for i,c in enumerate(commands) if 'apt-get install' in c),commands.index('lspci -Dnn'))
        self.assertFalse(any('apt-get install' in c and 'mst' in c for c in commands))

    def run_campaign(self, confirm=lambda _: 'yes', configure=None):
        def factory(*args):
            if configure:
                configure(self.fake)
            return self.fake
        with contextlib.redirect_stdout(io.StringIO()):
            return campaign(self.options,[target()],{},confirm=confirm,transport_factory=factory,runtime_root=self.root/'runtime')

    def test_cancel_discards_pre_and_sends_no_cycle(self):
        self.assertEqual(self.run_campaign(confirm=lambda _: 'no'),0)
        self.assertFalse(list(self.options.output.iterdir()))
        # Clean-start policy: PRE prepares the node (clears dmesg/SEL/logs) so the
        # baseline is clean, but no power/cycle command is ever sent on cancel.
        self.assertFalse(any(cmd in ('reboot','ipmitool power cycle','/usr/bin/stbypowerctrl.sh aux_cycle') for _,_,cmd in self.fake.calls))

    def test_messages_between_dmesg_read_and_clear_are_preserved(self):
        self.ready()
        original=self.fake.ssh
        def ssh(t,role,cmd,timeout=60,sudo=False):
            if cmd=='dmesg -c':
                return Command(0,'AER: Uncorrected (Fatal) error received\n')
            return original(t,role,cmd,timeout,sudo)
        self.fake.ssh=ssh
        result=self.session.one_loop(1)
        self.assertIn('DMESG_PCIE',[i['code'] for i in result['issues']])
        self.assertTrue((self.root/'tray1_n1'/'loop0001'/'dmesg_clear.txt').exists())
        self.assertTrue(any(item['code'] == 'DMESG_PCIE' for item in result['issues']))

    def test_campaign_reports_are_consistent_and_escaped(self):
        self.assertEqual(self.run_campaign(),1)
        output = next(self.options.output.iterdir())
        data = json.loads((output/'cycle_summary.json').read_text())
        self.assertEqual(data['state'],'COMPLETE')
        self.assertEqual(data['summary']['health'],'FAIL')
        self.assertEqual(data['nodes'][0]['completed'],2)
        self.assertEqual(len(data['summary']['issues']),1)
        data['nodes'][0]['pre']['issues'][0]['detail']='<script>alert(1)</script>'
        page=render_html(data)
        self.assertNotIn('<script>alert(1)</script>',page)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;',page)
        self.assertIn('KNOWN',page)
        self.assertTrue((output/'known_issues.md').exists())
        console_log = (output/'console.log').read_text()
        self.assertEqual(console_log.count('| PRE |'), 1)
        self.assertIn('| log clearing | PASS', console_log)
        self.assertEqual(rebuild(output)['state'],'COMPLETE')

    def test_run_id_uses_rack_timezone(self):
        fixed=datetime(2026,9,29,8,0,0,tzinfo=timezone.utc)
        def clock(tz=None):
            return fixed.astimezone(tz) if tz is not None else (fixed+timedelta(hours=8)).replace(tzinfo=None)
        with patch('neutrino_cycle.datetime') as mocked_clock:
            mocked_clock.now.side_effect=clock
            self.run_campaign()
        output=next(self.options.output.iterdir())
        self.assertTrue(output.name.startswith('neutrino_power_cycle_inband_20260929_160000_'),output.name)
        self.assertIn('Time zone: UTC+8 (local time in Run ID',(output/'console.log').read_text())

    def test_graceful_stop_keeps_current_loop_post(self):
        def callback():
            registry=next((self.root/'runtime').glob('run-*'))
            request_stop(registry.name.removeprefix('run-'),self.root/'runtime')
        self.fake.on_action=callback
        self.run_campaign()
        data=json.loads((next(self.options.output.iterdir())/'campaign.json').read_text())
        self.assertEqual(data['state'],'INCOMPLETE')
        self.assertEqual(data['nodes'][0]['completed'],1)

    def test_busy_endpoint_blocks_before_any_remote_command(self):
        locks = EndpointLocks(self.root/'runtime')
        locks.acquire(target(), 'already-running')
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                result = campaign(self.options, [target()], {}, confirm=lambda _: 'yes',
                                  transport_factory=lambda *_: self.fake, runtime_root=self.root/'runtime')
        finally:
            locks.close()
        self.assertEqual(result, 2)
        self.assertEqual(self.fake.calls, [])
        self.assertIn('BLOCKED', output.getvalue())
        self.assertIn('locked by another campaign', output.getvalue())

    def test_partial_blocked_scope_needs_confirmation(self):
        other=Target('tray2','n2','192.0.2.3','192.0.2.4','','')
        prompts=[]
        with contextlib.redirect_stdout(io.StringIO()):
            campaign(self.options,[target(),other],{},confirm=lambda prompt: prompts.append(prompt) or 'yes',
                     transport_factory=lambda *_:self.fake,runtime_root=self.root/'runtime')
        self.assertEqual(len(prompts),1)
        self.assertIn('1 runnable',prompts[0])
        data=json.loads((next(self.options.output.iterdir())/'campaign.json').read_text())
        self.assertTrue(data['nodes'][1]['blocked'])
        self.assertEqual(data['nodes'][1]['completed'],0)
        self.assertFalse(any(key=='tray2_n2' for key,_,_ in self.fake.calls))

    def test_crash_rebuild_keeps_partial_loop(self):
        self.run_campaign()
        output=next(self.options.output.iterdir())
        path=output/'campaign.json'
        data=json.loads(path.read_text())
        data['state']='RUNNING'
        # Simulate a crashed former process, not this still-live test owner.
        data['writer_owner']['process_token'] = 'terminated-test-owner'
        write_json(path,data)
        partial=new_record('LOOP 3');partial['loop']=3
        write_json(output/'tray1_n1'/'loop0003'/'report.json',partial)
        result=rebuild(output)
        self.assertEqual(result['state'],'INCOMPLETE')
        self.assertEqual(result['nodes'][0]['completed'],2)
        self.assertEqual(result['nodes'][0]['loops'][-1]['status'],'PENDING')

class LockTests(unittest.TestCase):
    def test_distinct_endpoints_parallel_and_overlap_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'runtime'
            first,second=EndpointLocks(root),EndpointLocks(root)
            try:
                first.acquire(target(),'one')
                with self.assertRaisesRegex(RuntimeError,'locked'):
                    second.acquire(target('n2'),'two')
                second.acquire(target('n2',offset=2),'two')
                first.close()
                first.acquire(target(),'three')
            finally:
                first.close();second.close()

    def test_stop_rejects_traversal(self):
        with self.assertRaises(ValueError):
            request_stop('../x')

class ConsolePaintTests(unittest.TestCase):
    def paint(self, line):
        console = Console()
        with patch('neutrino_cycle.COLOUR_ON', True):
            return console.paint(line)

    def test_system_and_phase_slots_are_coloured(self):
        out = self.paint('T L105-21R_n3 | LOOP 2 | FAIL')
        self.assertIn('\033[1;34mL105-21R_n3\033[0m', out)   # system: cyan
        self.assertIn('\033[1;35mLOOP 2\033[0m', out)        # phase: magenta
        self.assertIn('\033[1;31mFAIL\033[0m', out)          # status word: red

    def test_non_result_pipes_are_left_alone(self):
        out = self.paint('  Identity: BMC SSH OK | OS SSH OK')
        self.assertNotIn('\033[1;35m', out)                  # no phase slot
        self.assertIn('\033[1;32mOK\033[0m', out)            # OK still green

    def test_loop_progress_and_run_id(self):
        out = self.paint('Loop 3: waiting for 1 target(s)')
        self.assertIn('\033[1;35mLoop 3\033[0m', out)
        out = self.paint('Run ID: neutrino_power_cycle_inband_20260929_231617_690ec1')
        self.assertIn('\033[1;34mneutrino_power_cycle_inband_20260929_231617_690ec1\033[0m', out)

    def test_header_labels_are_coloured_but_timestamps_are_not(self):
        out = self.paint('2026-09-29T23:16:17+08:00 Mode: aux_cycle; channel: inband; loops: 5')
        self.assertIn('\033[1;35maux_cycle\033[0m', out)
        self.assertIn('\033[1;36m5\033[0m', out)
        self.assertNotIn('\033[1;36m2026', out)          # timestamp not recoloured
        self.assertNotIn('\033[1;36m23:', out)

    def test_status_words(self):
        self.assertIn('\033[1;31mSTOPPED\033[0m', self.paint('n3 | LOOP 1 | STOPPED'))
        self.assertIn('\033[1;33mWARN\033[0m', self.paint('  WARN [NEW] x: y'))
        self.assertIn('\033[1;32mCOMPLETE\033[0m', self.paint('n1 | PRE | COMPLETE'))

    def test_known_is_dim_but_unknown_is_not_matched(self):
        self.assertIn('\033[90mKNOWN\033[0m', self.paint('  FAIL [KNOWN] BF4: x'))
        self.assertNotIn('\033[90m', self.paint('UNKNOWN'))

    def test_colour_off_returns_plain_text(self):
        console = Console()
        with patch('neutrino_cycle.COLOUR_ON', False):
            line = 'T L105-21R_n1 | PRE | FAIL'
            self.assertEqual(console.paint(line), line)

if __name__ == '__main__':
    unittest.main()
