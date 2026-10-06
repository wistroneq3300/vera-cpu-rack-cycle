"""NIC badge/parser regressions (Item 4).

The hardware script emits two very different kinds of ``CHECK|NIC*`` lines:

* ``NIC`` / ``NIC_DEGRADED`` - real validation checks (does the expected count
  exist; how many slots are degraded). These must agree with the NIC finding.
* ``NIC_SLOT`` / ``NIC_MST_ROW`` / ``NIC_NON_CARD`` - evidence rows (raw
  per-slot inventory and the ``mst status`` line, and a GPU sitting on a NIC
  position). They must never be badged as a *health* PASS.

Before the fix the engine turned every ``CHECK|`` name into a health check and
defaulted it to PASS, so a record could show ``NIC_DEGRADED FAIL`` (the finding)
next to ``NIC_DEGRADED PASS`` (the check) and ``NIC_MST_ROW PASS`` for an
unhealthy card. No network access.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cycle_core import digest, parse_policy
from cycle_engine import NodeSession
from cycle_report import record_html
from cycle_transport import Command

import test_cycle as base


DEGRADED_OUTPUT = (
    'CHECK|NIC|actual=8|minimum=8\n'
    'CHECK|NIC_SLOT|slot=0002:00:00.0|state=DEGRADED|device_type=NA|mst_device=mt12184_pciconf0\n'
    'CHECK|NIC_MST_ROW|slot=0002:00:00.0|row=NA 0002:00:00.0 PCI device 15b3:1023\n'
    'CHECK|NIC_DEGRADED|detected=8|slots=0002:00:00.0\n'
    'ISSUE|NIC_DEGRADED|NIC|root port 0002:00:00.0 -> downstream Vera NIC (MST device mt12184_pciconf0) '
    "degraded: DEVICE_TYPE='NA' (expected Vera); card present but not functional (degraded slot 0002:00:00.0)\n"
    'RESULT|FAIL\n'
)

HEALTHY_OUTPUT = (
    'CHECK|NIC|actual=8|minimum=8\n'
    'CHECK|NIC_SLOT|slot=0002:00:00.0|state=PRESENT\n'
    'RE'
)  # replaced below to keep the literal short

HEALTHY_OUTPUT = (
    'CHECK|NIC|actual=8|minimum=8\n'
    'CHECK|NIC_SLOT|slot=0002:00:00.0|state=PRESENT\n'
    'RESULT|PASS\n'
)

NON_CARD_OUTPUT = (
    'CHECK|NIC|actual=8|minimum=8\n'
    'CHECK|NIC_NON_CARD|slot=0003:00:00.0|type=GB100\n'
    'RESULT|PASS\n'
)


class NicBadgeCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.options = SimpleNamespace(project='neutrino', cycle_mode='power_cycle', channel='inband',
                                       boot_timeout=.03, poll_interval=.001, loops=1, hours=0, cycle=True,
                                       config_script=base.BASE/'neutrino_config.sh',
                                       issue_policy=base.BASE/'issue_policy.md',
                                       output=self.root/'output', sensor_retry_delay=0)
        self.fake = base.FakeTransport({}, self.root/'ssh')
        self.session = NodeSession(base.target(), self.fake, self.root, 'test', b'script', digest(b'script'),
                                   self.options, parse_policy(self.options.issue_policy.read_text()))

    def tearDown(self):
        self.temp.cleanup()

    def serve(self, output):
        original = self.fake.ssh

        def ssh(t, role, cmd, timeout=60, sudo=False):
            if cmd.startswith('MEMORY_MIN_RATIO=') or cmd.startswith('bash '):
                self.fake.calls.append((t.key, role, cmd))
                return Command(1 if 'RESULT|FAIL' in output else 0, output)
            return original(t, role, cmd, timeout, sudo)
        self.fake.ssh = ssh

    def capture(self, output):
        self.serve(output)
        record = self.session.node['pre']
        self.session.capture(record)
        self.session.finish(record)
        return record


class ParserTests(NicBadgeCase):
    def test_degraded_check_is_not_a_pass(self):
        # (B) A real validation check must not report PASS while its finding is
        #     FAIL. NIC_DEGRADED is a check, not evidence.
        record = self.capture(DEGRADED_OUTPUT)
        self.assertNotEqual(record['hardware_checks'].get('NIC_DEGRADED'), 'PASS')
        self.assertNotEqual(record['check_summary'].get('NIC_DEGRADED'), 'PASS')

    def test_mst_row_is_not_a_health_check(self):
        # (C) A raw mst row is evidence, not a validation. It must not be
        #     badged PASS (or FAIL) as a hardware-health check.
        record = self.capture(DEGRADED_OUTPUT)
        self.assertNotIn('NIC_MST_ROW', record['hardware_checks'])
        self.assertNotIn('NIC_MST_ROW', record['check_summary'])

    def test_non_card_is_not_a_nic_failure(self):
        # (D) A GPU on a NIC position (EQ3300 GB100) must not become a NIC FAIL.
        record = self.capture(NON_CARD_OUTPUT)
        self.assertEqual(record['status'], 'PASS')
        self.assertNotIn('NIC_DEGRADED', [i['code'] for i in record['issues']])
        self.assertNotEqual(record['hardware_checks'].get('NIC_NON_CARD'), 'FAIL')
        self.assertNotIn('NIC_NON_CARD', record['hardware_checks'])

    def test_degraded_and_healthy_slots_coexist(self):
        # (A) One degraded + one healthy slot: the NIC check reflects the
        #     degraded finding; the healthy slot's inventory is retained.
        output = (
            'CHECK|NIC|actual=8|minimum=8\n'
            'CHECK|NIC_SLOT|slot=0002:00:00.0|state=DEGRADED|device_type=NA|mst_device=mt12184_pciconf0\n'
            'CHECK|NIC_SLOT|slot=0003:00:00.0|state=PRESENT\n'
            'CHECK|NIC_MST_ROW|slot=0002:00:00.0|row=NA 0002:00:00.0 PCI device 15b3:1023\n'
            'CHECK|NIC_DEGRADED|detected=8|slots=0002:00:00.0\n'
            'ISSUE|NIC_DEGRADED|NIC|degraded slot 0002:00:00.0; card present but not functional\n'
            'RESULT|FAIL\n'
        )
        record = self.capture(output)
        self.assertEqual(record['nic_slots'].get('0002:00:00.0'), 'DEGRADED')
        self.assertEqual(record['nic_slots'].get('0003:00:00.0'), 'PRESENT')
        self.assertNotEqual(record['check_summary'].get('NIC'), 'PASS')
        self.assertEqual(record['status'], 'FAIL')


class RenderTests(NicBadgeCase):
    def page(self, record):
        return record_html(record, 0)

    def test_degraded_record_has_no_conflicting_pass_badge(self):
        # (B/C) The rendered page must not show a PASS badge for NIC_DEGRADED or
        #       NIC_MST_ROW on a record whose NIC finding is FAIL.
        page = self.page(self.capture(DEGRADED_OUTPUT))
        self.assertNotIn('NIC_DEGRADED</strong><small class="raw-key">NIC_DEGRADED</small></td><td>'
                         '<span class="badge pass">PASS', page)
        # The NIC row itself must show the failure, not PASS.
        self.assertNotIn(
            'NIC validation</strong><small class="raw-key">NIC</small></td>'
            '<td><span class="badge pass">PASS', page)

    def test_evidence_row_not_rendered_as_health_pass(self):
        # (C) The raw mst row must not appear as a health check row at all.
        page = self.page(self.capture(DEGRADED_OUTPUT))
        self.assertNotIn('NIC_MST_ROW', page)

    def test_non_card_does_not_render_nic_failure(self):
        # (D) A GB100 non-card leaves the NIC health green.
        record = self.capture(NON_CARD_OUTPUT)
        page = self.page(record)
        self.assertNotIn('NIC_DEGRADED</strong>', page)
        self.assertNotIn('<span class="badge fail">FAIL</span></td><td>degraded slot', page)


if __name__ == '__main__':
    unittest.main()
