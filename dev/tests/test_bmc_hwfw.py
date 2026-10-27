"""PRE hardware/firmware inventory: reported for the record, never judged.

The inventory script is the operator's own; these tests pin the parts this
harness depends on - the section markers (which the script colours, so ANSI must
be stripped), the totals table, and the promise that nothing here becomes a
finding or a PASS/FAIL row.
"""
import unittest

import test_cycle as fixtures
from vera_cycle.core.cycle_transport import Command
from vera_cycle.engine.cycle_engine import HWFW_REMOTE, HWFW_RUN, NodeSession

# Trimmed capture from Neutrino10-n0 kept in the script's own format, ANSI
# colour codes included: the header colouring is what made the first version
# parse nothing at all.
SAMPLE = (
    '\n\x1b[36m[Info]\x1b[0m CPU\n 1: Vera A1Z\n 2: Vera A1Z\n'
    '\n\x1b[36m[Info]\x1b[0m DIMM (LPDDR5X)\n'
    'No.  Locator           Manu        PN                         SN            Size\n'
    ' 1:  LP5x_0_J174       Samsung     M564K6LC3CL0-CCVS8         3093855747    96 GB\n'
    '\n\x1b[36m[Info]\x1b[0m NVMe\n'
    'No.  PCI           NVMe      Model                        SN                Size       FW\n'
    ' 1:  000c:01:00.0  nvme0n1   HFS3T8GFPGX229N 0x1          3226BIF8T0013I010S2B  3.84 TB\n'
    '\n\x1b[33m[FW Version]\x1b[0m\n'
    'BMC IP : 10.36.72.203\n'
    '\nComponent                        Version\n'
    '-------------------------------- ------------------------------\n'
    'BIOS                             NV_SBIOS: 06.07.01.A2, OEM_SBIOS: 06.07.01.A2\n'
    'FW_BMC_0                         V256-2610-03.00\n'
    'FW_CPLD_0                        0.41\n'
    '\n\x1b[32m[Pass]\x1b[0m\n'
    'CPU: Vera A1Z x2\n'
    'DIMM: Samsung_M564K6LC3CL0-CCVS8 x16\n'
    'NVMe: HFS3T8GFPGX229N 0x1 x2\n'
    'PCIeFAB: PCI bridge: NVIDIA Corporation Device 2f95 x9\n'
    '\n\x1b[31m[Fail]\x1b[0m\n'
    '\nLost Device: BF4(DPU) x1\n'
)


class ParseTests(unittest.TestCase):
    def test_firmware_survives_the_script_colour_codes(self):
        firmware = NodeSession._parse_hwfw_firmware(SAMPLE)
        self.assertEqual(firmware['FW_BMC_0'], 'V256-2610-03.00')
        self.assertEqual(firmware['FW_CPLD_0'], '0.41')
        self.assertIn('06.07.01.A2', firmware['BIOS'])

    def test_bmc_ip_line_is_not_a_firmware_row(self):
        self.assertNotIn('BMC', NodeSession._parse_hwfw_firmware(SAMPLE))

    def test_totals_keep_type_component_and_quantity(self):
        totals = NodeSession._parse_hwfw_totals(SAMPLE)
        self.assertEqual(totals[0], ('CPU', 'Vera A1Z', 2))
        self.assertEqual(totals[1], ('DIMM', 'Samsung_M564K6LC3CL0-CCVS8', 16))

    def test_quantity_is_the_rightmost_token(self):
        # "HFS3T8GFPGX229N 0x1 x2" is two drives; a leftmost match would say one.
        totals = NodeSession._parse_hwfw_totals(SAMPLE)
        self.assertIn(('NVMe', 'HFS3T8GFPGX229N 0x1', 2), totals)

    def test_fail_section_never_becomes_totals(self):
        kinds = [t[0] for t in NodeSession._parse_hwfw_totals(SAMPLE)]
        self.assertNotIn('Lost Device', kinds)
        self.assertEqual(len(kinds), 4)

    def test_empty_output_parses_to_nothing(self):
        self.assertEqual(NodeSession._parse_hwfw_totals(''), [])
        self.assertEqual(NodeSession._parse_hwfw_firmware(''), {})


class CollectionTests(unittest.TestCase):
    setUp = fixtures.EngineTests.setUp
    tearDown = fixtures.EngineTests.tearDown

    def serve(self, output='', code=0, present=False):
        """Answer the probe and the run; leave other commands to the fixture."""
        original = self.fake.ssh
        self.pushed = []

        def ssh(t, role, cmd, timeout=60, sudo=False):
            if cmd.startswith('test -s ' + HWFW_REMOTE):
                return Command(0 if present else 1, '', 'RETURNED')
            if cmd == HWFW_RUN:
                self.fake.calls.append((t.key, role, cmd))
                return Command(code, output, 'RETURNED')
            return original(t, role, cmd, timeout, sudo)
        self.fake.ssh = ssh
        self.fake.upload_replace = lambda target, role, data, remote, mode=0o755: (
            self.pushed.append((role, remote, mode)))

    def test_present_script_is_not_pushed_again(self):
        self.serve(SAMPLE, present=True)
        self.session.collect_hwfw(self.session.node['pre'])
        self.assertEqual(self.pushed, [])

    def test_missing_script_is_pushed_to_its_own_path(self):
        self.serve(SAMPLE, present=False)
        self.session.collect_hwfw(self.session.node['pre'])
        self.assertEqual(len(self.pushed), 1)
        role, remote, mode = self.pushed[0]
        self.assertEqual(role, 'os')
        self.assertEqual(remote, HWFW_REMOTE)
        self.assertEqual(mode, 0o755)
        # The operator's own copy must never be the destination.
        self.assertNotIn('Config-Neutrino', remote)

    def test_collects_totals_and_firmware(self):
        self.serve(SAMPLE, present=True)
        self.session.collect_hwfw(self.session.node['pre'])
        hwfw = self.session.node['pre']['hwfw']
        self.assertEqual(hwfw['state'], 'COLLECTED')
        self.assertEqual(len(hwfw['totals']), 4)
        self.assertEqual(hwfw['firmware']['FW_BMC_0'], 'V256-2610-03.00')
        self.assertTrue(hwfw['evidence'])

    def test_inventory_produces_no_finding(self):
        self.serve(SAMPLE, present=True)
        self.session.collect_hwfw(self.session.node['pre'])
        self.assertEqual(self.session.node['pre']['issues'], [])

    def test_inventory_produces_no_pass_fail_row(self):
        # finish() turns every recorded command into a PASS/FAIL row; the
        # inventory is evidence, so it must stay out of ``commands``.
        self.serve(SAMPLE, present=True)
        record = self.session.node['pre']
        self.session.collect_hwfw(record)
        self.assertNotIn('hw_fw', record['commands'])
        self.session.finish(record)
        self.assertNotIn('hw_fw', record['check_summary'])

    def test_failed_run_is_recorded_without_a_finding(self):
        self.serve('', code=1, present=True)
        self.session.collect_hwfw(self.session.node['pre'])
        hwfw = self.session.node['pre']['hwfw']
        self.assertEqual(hwfw['state'], 'PARTIAL')
        self.assertEqual(hwfw['totals'], [])
        self.assertEqual(self.session.node['pre']['issues'], [])

    def test_push_failure_does_not_block_the_node(self):
        def broken(target, role, data, remote, mode=0o755):
            raise OSError('no space left on device')
        self.serve(SAMPLE, present=False)
        self.fake.upload_replace = broken
        record = self.session.node['pre']
        self.session.collect_hwfw(record)
        self.assertEqual(record['hwfw']['state'], 'UNAVAILABLE')
        self.assertIn('no space left', record['hwfw']['reason'])
        self.assertEqual(record['issues'], [])


class ReportTests(unittest.TestCase):
    def test_panel_shows_both_tables_and_no_verdict(self):
        from vera_cycle.reporting.cycle_report import _render_hwfw
        record = {'hwfw': {'state': 'COLLECTED',
                           'totals': [('CPU', 'Vera A1Z', 2), ('NIC', 'Vera(rev:0)', 17)],
                           'firmware': {'FW_CPLD_0': '0.41'},
                           'evidence': 'n0/pre_hw_fw.txt'}, 'evidence': ['n0/pre_hw_fw.txt']}
        html = _render_hwfw(record)
        self.assertIn('Hardware components', html)
        self.assertIn('Firmware versions', html)
        self.assertIn('Vera A1Z', html)
        self.assertIn('x17', html)
        self.assertIn('0.41', html)
        for word in ('PASS', 'FAIL', 'Pass', 'Fail'):
            self.assertNotIn(word, html)

    def test_unavailable_panel_says_so_without_a_verdict(self):
        from vera_cycle.reporting.cycle_report import _render_hwfw
        html = _render_hwfw({'hwfw': {'state': 'UNAVAILABLE', 'reason': 'push failed'}})
        self.assertIn('Not collected', html)
        self.assertIn('push failed', html)
        for word in ('PASS', 'FAIL'):
            self.assertNotIn(word, html)

    def test_absent_inventory_renders_nothing(self):
        from vera_cycle.reporting.cycle_report import _render_hwfw
        self.assertEqual(_render_hwfw({}), '')


if __name__ == '__main__':
    unittest.main()
