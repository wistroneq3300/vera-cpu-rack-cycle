import unittest
from unittest.mock import patch

import test_cycle as fixtures
import test_hardware_script as hardware
from cycle_core import aggregate_issues, classify_against_pre, dmesg_issues, issue_baseline, parse_sensors, sensor_issues
from cycle_transport import Command
from neutrino_cycle import show_result


def aer(name='BadTLP', bit=6, bdf='0000:01:00.0'):
    return (f'[ 1.0] pcieport {bdf}: PCIe Bus Error: severity=Correctable, type=Data Link Layer, (Receiver ID)\n'
            f'[ 1.1] pcieport {bdf}:   device [8086:1234] error status/mask={1 << bit:08x}/00000000\n'
            f'[ 1.2] pcieport {bdf}:    [{bit:2d}] {name}\n')


class ParserTests(unittest.TestCase):
    def test_aer_bits_identity_and_full_raw(self):
        pre = dmesg_issues(aer())
        post = classify_against_pre(dmesg_issues(aer('BadDLLP', 7)), issue_baseline(pre))
        self.assertNotEqual(pre[0]['fingerprint'], post[0]['fingerprint'])
        self.assertEqual(post[0]['classification'], 'NEW')
        self.assertEqual(post[0]['raw_lines'], [1, 2, 3])
        self.assertEqual(post[0]['error_bits'], [{'bit': 7, 'name': 'BadDLLP'}])
        self.assertIn('00000080/00000000', post[0]['raw'])
        self.assertIn('BadDLLP', post[0]['snippet'])
        integer_times = dmesg_issues(aer().replace('[ 1.0]', '[ 1]').replace('[ 1.1]', '[ 2]').replace('[ 1.2]', '[ 3]'))
        self.assertEqual(pre[0]['fingerprint'], integer_times[0]['fingerprint'])
        self.assertEqual(integer_times[0]['error_bits'], [{'bit': 6, 'name': 'BadTLP'}])

    def test_aer_interleaving_and_event_boundaries(self):
        first = aer().splitlines()
        other = aer('BadDLLP', 7, '0000:02:00.0').splitlines()
        items = dmesg_issues('\n'.join([first[0], other[0], first[1], other[1], first[2], other[2]]))
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]['raw_lines'], [1, 3, 5])
        self.assertEqual(items[1]['raw_lines'], [2, 4, 6])
        adjacent = dmesg_issues(aer() + aer('BadDLLP', 7))
        self.assertEqual(len(adjacent), 2)
        self.assertNotEqual(adjacent[0]['fingerprint'], adjacent[1]['fingerprint'])
        # An unrelated same-device line closes the event, not an unlimited BDF join.
        items = dmesg_issues(first[0] + '\npcieport 0000:01:00.0: unrelated status\n' + first[2])
        self.assertEqual(items[0]['raw_lines'], [1])
        # Severity does not change the identity of the same named error bit.
        fatal = dmesg_issues(aer().replace('Correctable', 'Uncorrectable (Fatal)'))
        self.assertEqual(dmesg_issues(aer())[0]['fingerprint'], fatal[0]['fingerprint'])

    def test_edac_reported_count_separate_from_observations(self):
        line = 'EDAC MC0: {} CE on DIMM1 (channel:0 address:0x123 syndrome:0x4)'
        pre, post = dmesg_issues(line.format(1)), dmesg_issues(line.format(5))
        self.assertEqual(pre[0]['fingerprint'], post[0]['fingerprint'])
        classify_against_pre(post, issue_baseline(pre))
        self.assertEqual(post[0]['classification'], 'WORSENED')
        self.assertEqual(post[0]['native_error_count'], 5)
        self.assertEqual(post[0]['occurrence_count'], 1)
        self.assertNotEqual(post[0]['fingerprint'], dmesg_issues(line.format(5).replace('DIMM1', 'DIMM2'))[0]['fingerprint'])
        self.assertNotEqual(post[0]['fingerprint'], dmesg_issues(line.format(5).replace(' CE ', ' UE '))[0]['fingerprint'])

    def test_sensor_del_c1_and_padding(self):
        for code in (0x7f, 0x9d, 0x00, 0xfffd):
            findings = sensor_issues(parse_sensors(f'CPU{chr(code)}Temp | 30 | degrees C | ok'))
            self.assertTrue(findings, f'Control character U+{code:04X} must not pass')
            self.assertEqual(findings[0]['code'], 'SENSOR_NAME_MALFORMED')
        self.assertFalse(sensor_issues(parse_sensors('CPU Temp\t | 30 | degrees C | ok')))


class ParserPipelineTests(unittest.TestCase):
    setUp = fixtures.EngineTests.setUp
    tearDown = fixtures.EngineTests.tearDown

    def test_aer_and_edac_engine_aggregate_console(self):
        self.fake.hardware_failure = False
        original = self.fake.ssh
        def ssh(t, role, cmd, timeout=60, sudo=False):
            if cmd in {'dmesg', 'dmesg -c'}:
                booted = self.fake.boots.get(t.key, 0) > 0
                return Command(0, (aer('BadDLLP', 7) if booted else aer()) +
                               f'EDAC MC0: {5 if booted else 1} CE on DIMM1 (address:0x123)\n')
            return original(t, role, cmd, timeout, sudo)
        with patch.object(self.fake, 'ssh', side_effect=ssh):
            self.session.precheck()
            self.session.start()
            record = self.session.one_loop(1)
        items = aggregate_issues({'nodes': [self.session.node]})
        self.assertEqual(len([i for i in items if i['code'] == 'DMESG_PCIE']), 2)
        new = next(i for i in record['issues'] if 'BadDLLP' in i['detail'])
        self.assertEqual(new['classification'], 'NEW')
        self.assertIn('BadDLLP', (self.root/new['evidence']).read_text())
        self.assertEqual(new['raw_lines'], [1, 2, 3])
        self.assertGreaterEqual(record['dmesg_native_error_counts']['WARN'], 5)
        output = []
        show_result(output.append, self.session.node, record)
        self.assertIn('BadDLLP', '\n'.join(output))
        self.assertIn('not lifetime counters', '\n'.join(output))


@unittest.skipUnless(hardware.SHELL, 'Bash required for isolated PATH fixtures')
class HardwareRun2Tests(unittest.TestCase):
    run_fixture = hardware.HardwareTests.run_fixture

    def test_cpu_row_accounting_matrix(self):
        cases = [
            ('0,0,Y\n1,1,Y\n', None, 0, 'logical=2|online=2'),
            ('0,0,Y\n1,1,Y\n2,,N\n', None, 1, 'logical=3|online=2'),
            ('0,0,Y\n1,1,Y\n2,,N\n', 'Unknown', 1, 'logical=3|online=2'),
            ('0,0,Y\n1,1,N\n', None, 1, 'logical=2|online=1'),
            ('0,0,Y\n1,1,Y\nmalformed\n', None, 1, 'row_errors=1'),
            ('0,0,Y\n1,1,Y\n1,1,Y\n', None, 1, 'row_errors=1'),
            ('0,0,Y\n1,1,maybe\n', None, 1, 'row_errors=1'),
        ]
        for project in ('neutrino', 'naboo'):
            for rows, threads, expected, evidence in cases:
                with self.subTest(project=project, rows=rows, threads=threads):
                    overrides = {'lscpu': "printf '%s' '" + rows + "'"}
                    if threads:
                        overrides['dmidecode'] = lambda s: s.replace('Status: Populated, Enabled', 'Thread Count: Unknown\\nStatus: Populated, Enabled')
                    result = self.run_fixture(project=project, overrides=overrides)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    self.assertIn(evidence, result.stdout)

    def test_pcie_device_type_matrix(self):
        cases = [
            ('Endpoint', True, False, False, False, 0),
            ('Legacy Endpoint', False, False, False, False, 1),
            ('Endpoint', False, False, False, False, 1),
            ('Root Complex Integrated Endpoint', False, False, False, False, 0),
            ('Root Complex Integrated Endpoint', True, False, False, False, 0),
            ('Root Complex Integrated Endpoint', True, True, False, False, 1),
            ('Root Complex Event Collector', False, False, False, False, 0),
            ('Root Complex Integrated Endpoint', False, False, True, False, 1),
            ('Root Complex Integrated Endpoint', False, False, False, True, 1),
        ]
        for project in ('neutrino', 'naboo'):
            for kind, link, downgrade, denied, cap, expected in cases:
                with self.subTest(project=project, kind=kind, link=link, denied=denied, cap=cap):
                    def transform(s):
                        s = s.replace('Express (v2) Endpoint', 'Express (v2) ' + kind)
                        if not link:
                            s = s.replace(' LnkSta: Speed 16GT/s, Width x8 ', ' LnkCap: Speed 16GT/s, Width x8' if cap else ' DevSta: CorrErr- UncorrErr- FatalErr-')
                        if denied:
                            s = s.replace('Express (v2) ' + kind, '<access denied>')
                        if downgrade:
                            s = s.replace('Width x8 ', 'Width x8 (downgraded)')
                        return s
                    result = self.run_fixture(project=project, overrides={'lspci': transform})
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    if expected:
                        self.assertIn('ISSUE|PCIE_', result.stdout)
                    elif not link:
                        self.assertIn('bdf=0000:01:00.0|state=unsupported', result.stdout)
