"""Unclassified dmesg error/fail lines must not vanish, and must not flood.

Real evidence: on the Vera CPU rack a boot capture held 103 error/fail lines
but the parser surfaced only one (an APEI corrected event). 92 lines were
silently dropped -- PCI io-window ``failed to assign``, ipmi_ssif probe
failures, tegra-bpmp debugfs, mlx_compat taint. These tests pin the fallback
sweep that collects them into one bundle, with IPMI transport failures
reported as FAIL because a broken SSIF makes ``ipmitool`` unusable.
"""
import unittest

from vera_cycle.core.cycle_core import (classify_against_pre, dmesg_issues, display_component, health,
                        issue_baseline)
from vera_cycle.reporting.cycle_report import _finding_html, _finding_html_compact

BOOT = '\n'.join([
    '[   11.87] pci 0001:00:00.0: bridge window [io  size 0x1000]: failed to assign',
    '[   11.87] pci 0002:02:00.0: BAR 2 [io  size 0x0080]: failed to assign',
    '[   11.86] PCI: OF: of_root node is NULL, cannot create PCI host bridge node',
    '[   15.45] tegra-bpmp NVDA3001:00: debugfs initialization failed: -27',
    '[   26.34] ipmi_ssif dmi-ipmi-ssif.1: probe with driver ipmi_ssif failed with error -17',
    '[   26.62] ipmi_si: Unable to find any System Interface(s)',
    '[   41.76] ipmi_ssif i2c-IPI0001:00: ipmi_ssif: Error fetching SSIF: -121 0 00, your system probably doesn\'t support this command so using defaults',
    '[   57.03] ipmi_ssif i2c-IPI0001:00: ipmi_ssif: Unable to clear message flags: 0 3 c1',
    '[   72.28] ipmi_ssif i2c-IPI0001:00: ipmi_ssif: Error getting global enables: -121 0 00',
    '[   28.00] mlx_compat: module verification failed: signature and/or required key missing - tainting kernel',
])


def by_code(items):
    return {item['code']: item for item in items}


class BundleTests(unittest.TestCase):
    def test_unclassified_lines_are_one_finding_not_many(self):
        items = dmesg_issues(BOOT)
        self.assertEqual(sorted(by_code(items)), ['DMESG_BUNDLE'])
        bundle = by_code(items)['DMESG_BUNDLE']
        texts = '\n'.join(e['text'] for e in bundle['entries'])
        self.assertIn('failed to assign', texts)
        self.assertIn('BAR 2', texts)
        self.assertIn('PCI: OF: of_root node is NULL', texts)
        self.assertIn('tegra-bpmp', texts)
        self.assertIn('mlx_compat', texts)

    def test_ipmi_transport_failure_is_fail(self):
        items = dmesg_issues(BOOT)
        bundle = by_code(items)['DMESG_BUNDLE']
        self.assertEqual(bundle['severity'], 'FAIL')
        self.assertEqual(health(items), 'FAIL')
        texts = '\n'.join(e['text'] for e in bundle['entries'])
        for needle in ('probe with driver ipmi_ssif failed',
                       'Unable to find any System Interface',
                       'Error fetching SSIF', 'Unable to clear message flags',
                       'Error getting global enables'):
            self.assertIn(needle, texts)

    def test_bundle_is_fail_when_ipmi_is_healthy(self):
        # Everything is FAIL for now; the operator adds a per-project allowlist
        # of known-benign lines later rather than the parser pre-judging them.
        benign = '\n'.join(line for line in BOOT.splitlines() if 'ipmi' not in line and 'tegra-bpmp' not in line)
        bundle = by_code(dmesg_issues(benign))['DMESG_BUNDLE']
        self.assertEqual(bundle['severity'], 'FAIL')
        self.assertEqual(health(dmesg_issues(benign)), 'FAIL')

    def test_normal_initialization_is_not_an_error(self):
        text = '\n'.join([
            'nvme nvme0: Shutdown timeout set to 10 seconds',
            'CPU features: detected: WFx with timeout',
            'sbsa-gwdt sbsa-gwdt.0: Initialized with 10s timeout @ 1000000000 Hz, action=0.',
            'AER: enabled error reporting',
            '0 errors',
        ])
        # Benign lines must not become a FAIL bundle; they now surface as an
        # INFO DMESG_NOISE finding instead of being dropped silently.
        codes = [item['code'] for item in dmesg_issues(text)]
        self.assertEqual(codes, ['DMESG_NOISE'])
        noise = next(item for item in dmesg_issues(text) if item['code'] == 'DMESG_NOISE')
        self.assertEqual(noise['severity'], 'INFO')

    def test_known_family_lines_are_not_double_counted(self):
        aer = ('[ 1.0] PCIe Bus Error: severity=Uncorrected (Fatal), type=Physical\n'
               '[ 1.1] pcieport 0001:00:00.0: AER: error status/mask=00000004/00002000\n')
        codes = [item['code'] for item in dmesg_issues(aer)]
        # The event is claimed by the PCIe family; its status/mask companion is
        # benign, so it must not be re-reported as a second FAIL in the bundle.
        self.assertIn('DMESG_PCIE', codes)
        self.assertNotIn('DMESG_BUNDLE', codes)

    def test_genuine_device_errors_are_not_treated_as_benign(self):
        # A bare nvme/mlx5/NVRM token used to sit in the benign list as a family
        # "continuation anchor", which silently dropped real device errors no
        # strict pattern claimed. Only true AER continuation markers may remain.
        for line, code in [('mlx5_core 0001:01:00.0: mlx5_cmd_check timeout', 'DMESG_BUNDLE'),
                           ('mlx5_core 0001:01:00.0: driver failed to load', 'DMESG_BUNDLE'),
                           ('nvme nvme0: I/O 12 QID 1 timeout, aborting', 'DMESG_NVME'),
                           ('nvme nvme0: controller is down; will reset', 'DMESG_NVME')]:
            with self.subTest(line=line):
                codes = [item['code'] for item in dmesg_issues(line)]
                self.assertIn(code, codes)
        # The benign normal-initialisation line is surfaced as DMESG_NOISE, never
        # as a FAIL bundle.
        benign = dmesg_issues('nvme nvme0: Shutdown timeout set to 10 seconds')
        self.assertEqual([i['code'] for i in benign], ['DMESG_NOISE'])
        self.assertEqual(benign[0]['severity'], 'INFO')

    def test_bundle_keeps_distinct_device_addresses(self):
        # Two cards logging the same failure text are two findings. Masking the
        # BDF in the dedup key hid the second card entirely.
        text = '\n'.join([
            '[ 1.0] mlx5_core 0001:01:00.0: mlx5_cmd_check timeout',
            '[ 1.1] mlx5_core 0002:01:00.0: mlx5_cmd_check timeout',
        ])
        bundle = by_code(dmesg_issues(text))['DMESG_BUNDLE']
        self.assertEqual(len(bundle['entries']), 2)
        texts = '\n'.join(e['text'] for e in bundle['entries'])
        self.assertIn('0001:01:00.0', texts)
        self.assertIn('0002:01:00.0', texts)

    def test_bundle_fingerprint_ignores_device_addresses(self):
        # The fingerprint keys the PRE comparison. It must not change when boot
        # re-enumerates BDFs, or a pre-existing bundle would be NEW every run.
        pre = dmesg_issues('pci 0001:00:00.0: BAR 2 [io size 0x0080]: failed to assign')
        same = dmesg_issues('pci 0001:00:00.0: BAR 2 [io size 0x0080]: failed to assign')
        moved = dmesg_issues('pci 0009:00:00.0: BAR 2 [io size 0x0080]: failed to assign')
        self.assertEqual(pre[0]['fingerprint'], same[0]['fingerprint'])
        self.assertEqual(pre[0]['fingerprint'], moved[0]['fingerprint'])
        self.assertEqual(classify_against_pre(moved, issue_baseline(pre))[0]['classification'], 'KNOWN')
        fresh = dmesg_issues('nvme0: probe failed -19')
        self.assertEqual(classify_against_pre(fresh, issue_baseline(pre))[0]['classification'], 'NEW')

    def test_display_component_labels_bundle_only(self):
        bundle = by_code(dmesg_issues('ipmi_ssif probe failed -17'))['DMESG_BUNDLE']
        self.assertEqual(display_component(bundle), 'fail/error')
        for item in dmesg_issues('PCIe Bus Error: severity=Uncorrectable (Fatal)'):
            self.assertEqual(display_component(item), 'pcie')
        apei = dmesg_issues('[ 1.0] {1}[Hardware Error]: Hardware error from APEI Generic Hardware Error Source: 8194\n'
                            '[ 1.1] {1}[Hardware Error]: event severity: fatal\n'
                            '[ 1.2] {1}[Hardware Error]: device: 0000:01:00.0\n')[0]
        self.assertEqual(display_component(apei), '0000:01:00.0')

    def test_card_renderers_survive_every_capture_shape(self):
        # An APEI-only capture has no bundle and a bundle-only capture has no
        # APEI; neither shape may be assumed present.
        apei = dmesg_issues('[ 1.0] {1}[Hardware Error]: Hardware error from APEI Generic Hardware Error Source: 8194\n'
                            '[ 1.1] {1}[Hardware Error]: event severity: fatal\n'
                            '[ 1.2] {1}[Hardware Error]: device: 0000:01:00.0\n')
        bundle = dmesg_issues('ipmi_ssif probe failed -17')
        for issues in ([], apei, bundle, apei + bundle):
            with self.subTest(count=len(issues)):
                record = dict(phase='LOOP 1', issues=issues)
                for rendered in (_finding_html(record), _finding_html_compact(record)):
                    # No issues is a benign empty card, not a crash and not a claim.
                    self.assertTrue('record-issues' in rendered or 'No issues recorded' in rendered)
                if issues:
                    self.assertIn('dmesg-block', _finding_html_compact(record))


BENIGN = ('CPU features: detected: WFx with timeout\n'
          'ERST: Error Record Serialization Table (ERST) support is initialized.\n'
          'EINJ: Error INjection is initialized.\n'
          'sbsa-gwdt sbsa-gwdt.0: Initialized with 10s timeout @ 1000000000 Hz, action=0.')
REAL = '[ 11.87] ipmi_ssif dmi-ipmi-ssif.1: probe with driver ipmi_ssif failed with error -17'


class BenignNoiseTests(unittest.TestCase):
    """The benign allowlist surfaces as INFO noise, never dropped, never FAIL."""

    def test_benign_lines_become_one_info_noise_finding(self):
        items = dmesg_issues(BENIGN)
        self.assertEqual([i['code'] for i in items], ['DMESG_NOISE'])
        self.assertEqual(items[0]['severity'], 'INFO')
        self.assertNotIn('DMESG_BUNDLE', [i['code'] for i in items])

    def test_noise_does_not_change_health(self):
        self.assertEqual(health(dmesg_issues(BENIGN)), 'PASS')
        # A genuine error alongside benign lines still fails, via the bundle.
        mixed = dmesg_issues(BENIGN + '\n' + REAL)
        self.assertEqual(health(mixed), 'FAIL')
        self.assertEqual([i['code'] for i in mixed if i['severity'] == 'INFO'], ['DMESG_NOISE'])

    def test_noise_is_separate_from_fail_bundle(self):
        items = dmesg_issues(BENIGN + '\n' + REAL)
        bundle = by_code(items)['DMESG_BUNDLE']
        noise = by_code(items)['DMESG_NOISE']
        self.assertEqual(bundle['severity'], 'FAIL')
        self.assertEqual(noise['severity'], 'INFO')
        # The real error must never leak into the benign noise, or vice versa.
        self.assertNotIn('ipmi_ssif', '\n'.join(e['text'] for e in noise['entries']))
        self.assertNotIn('WFx', '\n'.join(e['text'] for e in bundle['entries']))

    def test_noise_renders_collapsed_with_evidence_link(self):
        items = dmesg_issues(BENIGN + '\n' + REAL)
        for i in items:
            i['evidence'] = 'Neutrino0_n0/loop0001/dmesg_clear.txt'
            i['phase'] = 'dmesg_clear'
        html = _finding_html_compact(dict(phase='LOOP 1', issues=items))
        # Benign rows are visible (review only), collapsed, and carry a link.
        self.assertIn('dmesg-noise', html)
        self.assertIn('<details', html)
        self.assertIn('dmesg_clear.txt', html)
        self.assertIn('WFx', html)

    def test_package_and_compact_both_link_evidence(self):
        for renderer in (_finding_html, _finding_html_compact):
            items = dmesg_issues(REAL)
            items[0]['evidence'] = 'Neutrino0_n0/loop0001/dmesg_clear.txt'
            html = renderer(dict(phase='LOOP 1', issues=items))
            # Regression: the dmesg card used to omit the evidence link that
            # every other finding carries.
            self.assertIn('dmesg_clear.txt', html)

    def test_noise_is_shown_in_loop_and_summary_views(self):
        from vera_cycle.reporting.cycle_report import aggregate_issues
        items = dmesg_issues(BENIGN)
        for i in items:
            i['evidence'] = 'Neutrino0_n0/loop0001/dmesg_clear.txt'
        # Per-loop view.
        loop_html = _finding_html_compact(dict(phase='LOOP 1', issues=items))
        # Benign lines stay reviewable but collapsed (never affect health); the
        # label is the same fail/error group as every other dmesg block.
        self.assertIn('dmesg-noise', loop_html)
        self.assertIn('<details', loop_html)
        self.assertIn('fail/error', loop_html)
        # Whole-campaign summary aggregation keeps the noise finding.
        node = dict(key='n1', pre=dict(phase='PRE', issues=[]), loops=[dict(phase='LOOP 1', issues=items)], blocked=[])
        merged = aggregate_issues(dict(nodes=[node]))
        self.assertIn('DMESG_NOISE', [i['code'] for i in merged])
        self.assertTrue(all(i['severity'] == 'INFO' for i in merged if i['code'] == 'DMESG_NOISE'))


class FamilyVisibilityTests(unittest.TestCase):
    """Every parsed dmesg family must reach the report.

    Regression: ``_visible_issues`` kept only the catch-all bundle, so an EDAC
    uncorrectable or an NVMe timeout raised the health verdict while the page
    showed nothing but the bundle -- the finding existed and was hidden.
    """

    LINES = '\n'.join([
        '[ 20.0] EDAC MC0: 1 CE memory read error on CPU_SrcID#0_MC#0_Chan#0_DIMM#0',
        '[ 21.0] nvme0: I/O 145 QID 1 timeout, aborting',
        '[ 22.0] pcieport 0000:01:00.0: AER: device recovery failed',
        '[ 23.0] Kernel panic - not syncing: Fatal exception',
    ])

    def test_each_family_is_rendered(self):
        items = dmesg_issues(self.LINES)
        for item in items:
            item['evidence'] = 'n/loop0001/dmesg_clear.txt'
        html = _finding_html_compact(dict(phase='LOOP 1', issues=items))
        for needle in ('EDAC', 'nvme0', 'pcieport', 'Kernel panic'):
            self.assertIn(needle, html)
        codes = {i['code'] for i in items}
        self.assertIn('DMESG_EDAC', codes)
        self.assertIn('DMESG_NVME', codes)
        self.assertIn('DMESG_KERNEL', codes)

    def test_dmesg_cards_carry_no_known_new_badge(self):
        items = dmesg_issues(self.LINES)
        classify_against_pre(items, set())
        html = _finding_html_compact(dict(phase='LOOP 1', issues=items))
        # dmesg blocks are shown as the log itself; KNOWN/NEW badges on them
        # were unreadable and are gone from both the card and the tally.
        self.assertNotIn('>NEW<', html)
        self.assertNotIn('>KNOWN<', html)

    def test_bundle_count_is_stable_across_membership_changes(self):
        # Two captures whose BENIGN content differs must not re-report the
        # error lines as fresh; the displayed messages are what matters.
        first = dmesg_issues(self.LINES)
        second = dmesg_issues(self.LINES + '\n[ 24.0] ipmi_si: Unable to find any System Interface(s)')
        first_bundle = [e['text'] for i in first if i['code'] == 'DMESG_BUNDLE'
                        for e in i.get('entries', [])]
        second_bundle = [e['text'] for i in second if i['code'] == 'DMESG_BUNDLE'
                         for e in i.get('entries', [])]
        self.assertTrue(set(first_bundle) <= set(second_bundle))


class CrossCaptureIdentityTests(unittest.TestCase):
    """A second device failing the same way must survive as its own finding.

    Real failure this pins: 0000:01:00.0 logged ``BAR assignment failed`` on the
    first capture, then 0000:02:00.0 logged the same text on the next one. The
    bundle signature normalised the BDF away, so the engine's (boot, raw) delta
    treated the second capture as a repeat and the second card never reached the
    report -- a newly failing device was invisible on the page that is supposed
    to prove no such thing happened.

    Identity is per (device, message). Normalisation may still collapse repeats
    for presentation, but it must never decide whether an observation exists.
    """

    def bundle(self, text):
        return [e for e in dmesg_issues(text) if e['code'] == 'DMESG_BUNDLE']

    def test_second_bdf_is_a_distinct_observation(self):
        first = '[ 10.0] pcieport 0000:01:00.0: BAR assignment failed\n'
        second = first + '[ 20.0] pcieport 0000:02:00.0: BAR assignment failed\n'
        one, two = self.bundle(first), self.bundle(second)
        self.assertEqual(len(one), 1)
        self.assertEqual(len(two), 1)
        # The raw signature may normalise, but the observation identity may not
        # lose the device: that is what the delta compares.
        devices_one = {d for e in one for d in e['device']}
        devices_two = {d for e in two for d in e['device']}
        self.assertIn('0000:01:00.0', devices_one)
        self.assertIn('0000:02:00.0', devices_two)
        self.assertNotEqual(self.identity(one[0]), self.identity(two[0]))

    def identity(self, event):
        return tuple(sorted(event.get('observations') or []))

    def test_same_device_repeat_keeps_its_count(self):
        text = ('[ 10.0] pcieport 0000:01:00.0: BAR assignment failed\n'
                '[ 11.0] pcieport 0000:01:00.0: BAR assignment failed\n'
                '[ 12.0] pcieport 0000:01:00.0: BAR assignment failed\n')
        event = self.bundle(text)[0]
        # occurrence_count is what the engine sums; it said 1 for three lines.
        self.assertEqual(event['occurrence_count'], 3)
        self.assertEqual(event['entries'][0]['count'], 3)

    def test_multiset_delta_does_not_double_count(self):
        text = '[ 10.0] pcieport 0000:01:00.0: BAR assignment failed\n'
        twice = text + '[ 11.0] pcieport 0000:01:00.0: BAR assignment failed\n'
        one = self.bundle(text)[0]
        two = self.bundle(twice)[0]
        self.assertEqual(one['occurrence_count'], 1)
        self.assertEqual(two['occurrence_count'], 2)
        # Overlapping captures: the second read repeats the first line only.
        self.assertEqual(two['occurrence_count'] - one['occurrence_count'], 1)

    def test_different_devices_same_error_are_not_swallowed(self):
        text = ('[ 10.0] pcieport 0000:01:00.0: BAR assignment failed\n'
                '[ 11.0] pcieport 0000:02:00.0: BAR assignment failed\n')
        event = self.bundle(text)[0]
        self.assertEqual(event['occurrence_count'], 2)
        self.assertEqual(len(event['entries']), 2)
        self.assertEqual({d for d in event['device']}, {'0000:01:00.0', '0000:02:00.0'})

    def test_raw_evidence_keeps_the_original_text(self):
        # raw is used as a dedupe key, so it may normalise for comparison, but
        # the original line must remain readable in the evidence trail.
        text = '[ 10.0] pcieport 0000:02:00.0: BAR assignment failed\n'
        event = self.bundle(text)[0]
        self.assertIn('0000:02:00.0', ' '.join(event['raw_lines_text'] if 'raw_lines_text' in event
                                               else [e['text'] for e in event['entries']]))
