"""BMC I2C inventory: captured evidence only, never a finding."""
import unittest

import test_cycle as fixtures
from test_cycle import target
from vera_cycle.core.cycle_core import digest, parse_policy
from vera_cycle.engine.cycle_engine import I2C_SCAN, NodeSession, _bus_sort_key

HEADER = '     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f\n'


def bus(n, *addrs):
    """Render one i2cdetect table covering only the rows the addresses fall in."""
    rows = {'0': [], '1': [], '2': [], '3': [], '4': [], '5': [], '6': [], '7': []}
    for addr in addrs:
        value = int(addr, 16)
        rows[f'{(value >> 4):x}'].append((value & 0xf, addr))
    lines = [f'@BUS {n}', HEADER]
    for prefix in ('0', '1', '2', '3', '4', '5', '6', '7'):
        if not rows[prefix]:
            continue
        cells = ['--'] * 16
        for index, addr in rows[prefix]:
            cells[index] = addr
        lines.append(f'{prefix}0: ' + ' '.join(cells))
    return '\n'.join(lines) + '\n'


class SplitTests(unittest.TestCase):
    def test_splits_every_bus_and_keeps_order(self):
        output = bus(0) + bus(81, '40', '41') + bus(9)
        sections = NodeSession._split_i2c_scan(output)
        self.assertEqual(sorted(sections, key=_bus_sort_key), ['0', '9', '81'])
        self.assertIn('40', sections['81'])

    def test_bus_sort_is_numeric_not_lexical(self):
        buses = ['0', '1', '9', '10', '60', '87']
        self.assertEqual(sorted(buses, key=_bus_sort_key), ['0', '1', '9', '10', '60', '87'])

    def test_probe_error_keeps_a_visible_section(self):
        output = '@BUS 5\n' + HEADER + '@ERROR i2c-5 exit 124\n@BUS 6\n' + HEADER
        sections = NodeSession._split_i2c_scan(output)
        self.assertIn('@ERROR', sections['5'])
        self.assertEqual(sorted(sections), ['5', '6'])

    def test_empty_output_yields_nothing(self):
        self.assertEqual(NodeSession._split_i2c_scan(''), {})

    def test_scan_command_covers_every_advertised_bus(self):
        self.assertIn('i2cdetect -l', I2C_SCAN)
        self.assertIn('sort -n', I2C_SCAN)
        self.assertIn('timeout 15', I2C_SCAN)
        # Read-byte mode only: a write probe can disturb a live device.
        self.assertIn('-y -r', I2C_SCAN)
        self.assertNotIn('-y -W', I2C_SCAN)


class CollectionTests(unittest.TestCase):
    setUp = fixtures.EngineTests.setUp
    tearDown = fixtures.EngineTests.tearDown

    def serve_i2c(self, output, code=0, state='RETURNED'):
        """Answer the I2C scan, leaving every other command to the fixture."""
        from vera_cycle.core.cycle_transport import Command
        original = self.fake.ssh

        def ssh(t, role, cmd, timeout=60, sudo=False):
            if cmd == I2C_SCAN:
                self.fake.calls.append((t.key, role, cmd))
                return Command(code, output, state)
            return original(t, role, cmd, timeout, sudo)
        self.fake.ssh = ssh

    SCAN = (bus(0) + bus(81, '40', '41', '60', '6b') + bus(87))

    def test_i2c_is_collected_and_written_per_bus(self):
        self.serve_i2c(self.SCAN)
        self.session.precheck()
        folder = self.root / 'tray1_n1' / 'i2cdetect'
        buses = self.session.node['pre']['i2c']['buses']

        self.assertEqual(self.session.node['pre']['i2c']['state'], 'COLLECTED')
        self.assertEqual(buses, ['0', '81', '87'])
        for name in ('all.txt', 'i2c-0.txt', 'i2c-81.txt', 'i2c-87.txt'):
            self.assertTrue((folder / name).is_file(), f'{name} missing')
        self.assertIn('i2cdetect -y -r 81', (folder / 'i2c-81.txt').read_text())
        self.assertIn('6b', (folder / 'i2c-81.txt').read_text())

    def test_i2c_never_produces_a_finding(self):
        self.serve_i2c(self.SCAN)
        self.session.precheck()
        issues = self.session.node['pre']['issues']
        self.assertFalse([i for i in issues if 'i2c' in str(i).lower()])

    def test_loop_captures_its_own_i2c_folder(self):
        self.serve_i2c(self.SCAN)
        self.session.precheck()
        self.session.start()
        record = self.session.one_loop(1)
        self.assertIn('i2c', record)
        path = self.root / record['i2c']['path']
        self.assertTrue((path / 'all.txt').is_file())
        self.assertIn('loop0001', str(path))

    def test_each_loop_scans_its_buses_once(self):
        self.serve_i2c(self.SCAN)
        self.session.precheck()
        self.session.start()
        before = sum(1 for _, _, cmd in self.fake.calls if cmd == I2C_SCAN)
        self.session.one_loop(1)
        after = sum(1 for _, _, cmd in self.fake.calls if cmd == I2C_SCAN)
        self.assertEqual(after - before, 1, 'a loop must scan once, not on both capture passes')

    def test_failed_probe_does_not_stop_the_node(self):
        self.serve_i2c('', code=124, state='RESPONSE_LOST')
        self.session.precheck()
        # A wedged scan must not block the node or invent a hardware finding.
        self.assertNotIn('PRE_BLOCKED', {i['code'] for i in self.session.node['pre']['issues']})
        self.assertEqual(self.session.node['pre']['i2c']['state'], 'EMPTY')


if __name__ == '__main__':
    unittest.main()
