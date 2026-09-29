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
from cycle_engine import NodeSession, new_record
from cycle_report import render_html, rebuild, status
from cycle_runtime import EndpointLocks, request_stop
from cycle_transport import Command, IdentityUnsafe
from neutrin_cycle import BASE, campaign, main

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
        if cmd.startswith('bash '):
            return Command(1, 'ISSUE|BF4_MISSING|BF4|Expected at least 1; detected 0\nRESULT|FAIL\n') if self.hardware_failure else Command(0, 'RESULT|PASS\n')
        if cmd == '/usr/bin/powerctrl.sh power_status':
            return Command(0, 'Host: Running\nChassis Power: On')
        return Command(0, 'available\n')

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
        if cmd == 'power cycle':
            return self.action(t)
        if cmd == 'power status':
            return Command(0, 'Chassis Power is ' + ('off' if self.power_off else 'on'))
        if cmd == 'sel elist':
            return Command(0, '1 | 09/29/2026 | 10:00:00 | System boot | Asserted\n')
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

    def test_aggregation_preserves_failure_and_campaign_classification(self):
        # The mechanism is exercised with a rule declared here, not the shipped
        # policy file, so it stays valid whatever the production policy contains.
        rules=parse_policy('| neutrino | BF4_MISSING | BF4 | KNOWN | local test rule | yes |')
        pre=new_record('PRE')
        post=new_record('LOOP 1')
        pre['issues']=classify([issue('BF4_MISSING','BF4','first','WARN')],'neutrino',rules)
        post['issues']=classify([issue('BF4_MISSING','BF4','second','FAIL')],'neutrino',rules)
        data={'nodes':[{'key':'tray_n1','pre':pre,'loops':[post]}]}
        for first,second in ((pre,post),(post,pre)):
            data['nodes'][0].update(pre=first,loops=[second])
            merged=aggregate_issues(data)
            self.assertEqual(len(merged),1)
            self.assertEqual(merged[0]['severity'],'FAIL')
            self.assertEqual(merged[0]['classification'],'KNOWN')
            self.assertEqual(len(merged[0]['occurrences']),2)

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
            '\ufffd\ufffd\ufffd\ufffd | na |  | na | na\n'
        )
        self.assertEqual(sensor_issues(rows), [])
        self.assertEqual(
            health(sensor_issues(parse_sensors('Fan | na | percent | na'))),
            'FAIL',
        )
        self.assertEqual(
            health(sensor_issues(parse_sensors('\ufffd\ufffd\ufffd\ufffd | na | percent | na'))),
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
        self.assertEqual(parsed['0001:01:00.0'], '10de:2f95')
        self.assertEqual(len(pci_issues(parsed, parse_pci(PCI.replace('1234:5678','1234:9999')))), 1)

    def test_pcie_downgrade_is_always_a_failure(self):
        text = (
            '[Evidence] PCIe-links\n'
            '0004:01:00.0 Non-Volatile memory controller: KIOXIA NVMe\n'
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

    def test_bf4_absent_is_known_failure_under_shipped_policy(self):
        # The missing card is known to the operator, but it remains a real FAIL.
        rule = parse_policy((BASE / 'issue_policy.md').read_text())
        items = classify([issue('BF4_MISSING','BF4','missing')], 'neutrino', rule)
        self.assertEqual(items[0]['classification'], 'KNOWN')
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
                                       config_script=BASE/'vera_rack.sh',issue_policy=BASE/'issue_policy.md',output=self.root/'output')
        self.fake = FakeTransport({}, self.root/'ssh')
        self.session = NodeSession(target(),self.fake,self.root,'test',b'script',digest(b'script'),self.options,
                                   parse_policy(self.options.issue_policy.read_text()))

    def tearDown(self):
        self.temp.cleanup()

    def ready(self):
        self.session.precheck()
        self.assertFalse(self.session.node['blocked'])
        self.session.start()

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
            if cmd=='sel elist':
                return Command(0,'SEL has no entries\nGet SEL Info command failed')
            return original(t,cmd,timeout)
        self.fake.oob=oob
        result=self.session.one_loop(1)
        self.assertIn('IPMI_REPORTED_ERROR',[i['code'] for i in result['issues']])

    def test_pre_sel_error_is_never_cleared(self):
        original=self.fake.oob
        def oob(t,cmd,timeout=30):
            if cmd=='sel elist':
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

    def test_failed_dmesg_clear_still_attempts_sel_without_key_error(self):
        self.session.precheck()
        original=self.fake.ssh
        def ssh(t,role,cmd,timeout=60,sudo=False):
            return Command(1,'permission denied') if cmd=='dmesg -c' else original(t,role,cmd,timeout,sudo)
        self.fake.ssh=ssh
        self.session.start()
        self.assertFalse(self.session.node['pre']['commands']['start_dmesg_clear']['valid'])
        self.assertTrue(self.session.node['pre']['commands']['start_sel_clear']['valid'])
        self.assertEqual(sum(cmd=='sel clear' for _,_,cmd in self.fake.calls),1)

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
        result = self.session.one_loop(1)
        self.assertIn('SENSOR_RECOVERED',[i['code'] for i in result['issues']])
        self.assertTrue((self.root/'tray1_n1'/'loop0001'/'sensor_confirm.txt').exists())

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

    def test_outband_reboot_off_then_on(self):
        self.options.cycle_mode='reboot'
        self.options.channel='outband'
        self.ready()
        result=self.session.one_loop(1)
        self.assertEqual([a['command'] for a in result['action']],['power soft','power on'])
        self.assertTrue(result['recovery']['power_off_observed'])

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
        self.assertFalse(any(cmd in ('dmesg -c','sel clear','ipmitool power cycle') for _,_,cmd in self.fake.calls))

    def test_messages_between_dmesg_read_and_clear_are_preserved(self):
        self.ready()
        original=self.fake.ssh
        def ssh(t,role,cmd,timeout=60,sudo=False):
            if cmd=='dmesg -c':
                return Command(0,'AER: Uncorrected (Fatal) error received\n')
            return original(t,role,cmd,timeout,sudo)
        self.fake.ssh=ssh
        result=self.session.one_loop(1)
        self.assertIn('DMESG_HARDWARE',[i['code'] for i in result['issues']])
        self.assertNotIn('Uncorrected',(self.root/'tray1_n1'/'loop0001'/'dmesg_clear.txt').read_text())
        self.assertTrue(any(item['code'] == 'DMESG_HARDWARE' for item in result['issues']))

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
        self.assertIn('| log clearing | complete', console_log)
        self.assertEqual(rebuild(output)['state'],'COMPLETE')

    def test_run_id_uses_rack_timezone(self):
        fixed=datetime(2026,9,29,8,0,0,tzinfo=timezone.utc)
        def clock(tz=None):
            return fixed.astimezone(tz) if tz is not None else (fixed+timedelta(hours=8)).replace(tzinfo=None)
        with patch('neutrin_cycle.datetime') as mocked_clock:
            mocked_clock.now.side_effect=clock
            self.run_campaign()
        output=next(self.options.output.iterdir())
        self.assertTrue(output.name.startswith('neutrino_20260929_160000+0800_'),output.name)
        self.assertIn('Time zone: UTC+8 (+0800 in Run ID',(output/'console.log').read_text())

    def test_graceful_stop_keeps_current_loop_post(self):
        def callback():
            registry=next((self.root/'runtime').glob('run-*'))
            request_stop(registry.name.removeprefix('run-'),self.root/'runtime')
        self.fake.on_action=callback
        self.run_campaign()
        data=json.loads((next(self.options.output.iterdir())/'campaign.json').read_text())
        self.assertEqual(data['state'],'INCOMPLETE')
        self.assertEqual(data['nodes'][0]['completed'],1)

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

if __name__ == '__main__':
    unittest.main()
