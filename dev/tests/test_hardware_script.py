"""Run neutrino_config.sh against PATH stubs, never the host's hardware tools."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

BASE=Path(__file__).resolve().parents[2]
SHELL=os.environ.get('VERA_TEST_SHELL') or shutil.which('bash')

@unittest.skipUnless(SHELL,'Set VERA_TEST_SHELL to a Bash executable')
class HardwareTests(unittest.TestCase):
    def run_fixture(self, dimms=16, bf4='BlueField-4', downgrade=False, functions=2, serials=None, endpoint=True, unavailable=False, project='neutrino', overrides=None, ratio='0.90', mode=None):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            serials = ['CARD-A'] * functions if serials is None else serials
            identities = '\n'.join(f"0000:0{i+4}:00.0 Ethernet controller: Mellanox {bf4}\n Capabilities: [54] Vital Product Data\n [SN] Serial number: {serial}" for i, serial in enumerate(serials))
            pci_functions = '\n'.join(f"0000:0{i+4}:00.0 Ethernet controller [0200]: Mellanox {bf4} [15b3:a2dc]" for i in range(functions))
            pci_inventory = '\n'.join(f'0000:{i:02x}:00.0 PCI bridge [0604]: NVIDIA bridge [10de:2f95]' for i in range(16, 36)) + '\n' + pci_functions + '\n0000:02:00.0 USB controller [0c03]: controller [1234:5678]\n0000:03:00.0 PCI bridge [0604]: ASPEED AST1150 [1234:9876]\n0000:01:00.0 Ethernet controller [0200]: Mellanox ConnectX test endpoint'
            link_inventory = pci_inventory.replace('0000:01:00.0 Ethernet controller [0200]: Mellanox ConnectX test endpoint', f"0000:01:00.0 Ethernet controller [0200]: Mellanox ConnectX test endpoint\n Capabilities: [80] Express (v2) {'Endpoint' if endpoint else 'Root Port'}\n LnkSta: Speed {'unknown, Width x0' if unavailable else '16GT/s, Width x8'} {'(downgraded)' if downgrade else ''}")
            # ``lspci -Dvv -nn`` carries link status AND VPD serials in one dump,
            # so the fixtures feed BF4 blocks through the same verbose output the
            # checks now share instead of a separate ``-Dvvv`` capture.
            verbose_inventory = link_inventory
            for i, serial in enumerate(serials):
                verbose_inventory = verbose_inventory.replace(
                    f"0000:0{i+4}:00.0 Ethernet controller [0200]: Mellanox {bf4} [15b3:a2dc]",
                    f"0000:0{i+4}:00.0 Ethernet controller [0200]: Mellanox {bf4} [15b3:a2dc]\n Capabilities: [54] Vital Product Data\n [SN] Serial number: {serial}")
            tools={
              'dmidecode':f'''case "$*" in
                '-t processor') printf 'Status: Populated, Enabled\\nStatus: Populated, Enabled\\n';;
                '-t memory') i=1; while [ "$i" -le {dimms} ]; do printf 'Memory Device\\n Size: 128 GB\\n'; i=$((i+1)); done; printf 'Memory Device\\n Size: No Module Installed\\n';;
                *) echo 'Version: example';; esac''',
              'nvme':"printf '/dev/nvme0n1 disk0\\n/dev/nvme0n2 namespace2\\n/dev/nvme1n1 disk1\\n'",
              'lscpu':"printf '# CPU,Socket,Online\\n0,0,Y\\n1,1,Y\\n'",
              'cat':"printf 'MemTotal: 2000000000 kB\\n'",
              'mst':f'''i=1; while [ "$i" -le 22 ]; do printf 'Vera(rev:0) /dev/mst/device %04x:01:00.0\\n' "$i"; i=$((i+1)); done
                        echo '{bf4}(rev:0) /dev/mst/dpu 0000:02:00.0' ''',
              'lspci':f'''case "$*" in
                    *-Dvv\\ -nn*) printf '%s\\n' '{verbose_inventory}';;
                    -Dvv) printf '%s\\n' '{verbose_inventory}';;
                    -Dvvv) printf '%s\\n' '{identities}';;
                    *) printf '%s\\n' '{pci_inventory}';;
                  esac''',
              'ipmitool':"echo 'Firmware Revision: example'"}
            for name, transform in (overrides or {}).items():
                tools[name] = transform(tools[name]) if callable(transform) else transform
            # POSIX sh stubs so the harness runs under both dash and Git Bash.
            for name,content in tools.items():
                file=root/name
                file.write_text('#!/usr/bin/env sh\n'+content+'\n',encoding='utf-8',newline='\n')
                file.chmod(0o755)
            env={**os.environ,'MEMORY_MIN_RATIO':ratio,'PATH':str(root)+os.pathsep+str(Path(SHELL).parent)+os.pathsep+os.environ.get('PATH','')}
            argv=[SHELL,str(BASE/f'{project}_config.sh')]+([mode] if mode else [])
            result=subprocess.run(argv,env=env,capture_output=True,text=True,encoding='utf-8',timeout=45,check=False)
            return result

    def test_populated_16_pass_and_namespace_dedup(self):
        result=self.run_fixture()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('CHECK|NVMe|actual=2',result.stdout)
        self.assertIn('RESULT|PASS',result.stdout)

    def test_extra_dimm_fails(self):
        result=self.run_fixture(dimms=17)
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertIn('ISSUE|DIMM_COUNT',result.stdout)

    def test_bf3_never_counts_as_bf4(self):
        for model in ('BlueField-3','BlueField','ConnectX-9','DPU'):
            with self.subTest(model=model):
                result=self.run_fixture(bf4=model)
                self.assertEqual(result.returncode,1,result.stdout+result.stderr)
                self.assertIn('ISSUE|BF4_MISSING',result.stdout)

    def test_bf4_check_reports_source_counts(self):
        # A missing device has no offending row to quote, so the CHECK line must
        # carry where the card was looked for and how many were found there.
        result=self.run_fixture(bf4='BlueField-3')
        self.assertIn('CHECK|BF4|actual=0|exact=1|pci_functions=0',result.stdout)

    def test_bf4_present_passes_and_counts(self):
        result=self.run_fixture(bf4='BlueField-4')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('CHECK|BF4|actual=1|exact=1|pci_functions=2',result.stdout)

    def test_downgrade_is_failure_with_bdf(self):
        result=self.run_fixture(downgrade=True)
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertIn('ISSUE|PCIE_DOWNGRADE|0000:01:00.0',result.stdout)
        self.assertIn('CHECK|PCIE_DOWNGRADE|bdf=0000:01:00.0|lnksta=',result.stdout)

    def test_distinct_serials_are_two_cards_and_exact_count_fails(self):
        result = self.run_fixture(serials=['CARD-A', 'CARD-B'])
        self.assertIn('ISSUE|BF4_COUNT|BF4', result.stdout)
        self.assertIn('CHECK|BF4|actual=2|exact=1', result.stdout)

    def test_partial_identity_never_guesses_card_count(self):
        result = self.run_fixture(serials=['CARD-A', ''])
        self.assertIn('ISSUE|BF4_IDENTITY_UNAVAILABLE', result.stdout)
        self.assertEqual(result.returncode, 1)

    def test_bridge_downgrade_is_not_endpoint_failure(self):
        result = self.run_fixture(downgrade=True, endpoint=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_endpoint_unavailable_fails(self):
        result = self.run_fixture(unavailable=True)
        self.assertIn('ISSUE|PCIE_LINK_UNAVAILABLE', result.stdout)

    def test_naboo_configuration(self):
        result = self.run_fixture(project='naboo')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_review_hardware_failures_for_both_projects(self):
        scenarios = [
            ({'lscpu': "printf '0,0,Y\\n1,1,N\\n'"}, 'CPU_TOPOLOGY'),
            ({'dmidecode': lambda s: s.replace('Populated, Enabled\\nStatus: Populated, Enabled', 'Populated, Enabled\\nStatus: Populated, Disabled By BIOS')}, 'CPU_DISABLED'),
            ({'cat': "printf 'MemTotal: 1000000000 kB\\n'"}, 'MEMORY_VISIBLE'),
            ({'mst': "i=0; while [ $i -lt 22 ]; do echo 'Vera(rev:0) /dev/mst/device 0001:01:00.0'; i=$((i+1)); done"}, 'DUPLICATE_BDF'),
            ({'lspci': lambda s: s.replace(' LnkSta: Speed 16GT/s, Width x8 ', ' LnkCap: Speed 16GT/s, Width x8 ')}, 'PCIE_LINK_UNAVAILABLE'),
            ({'lspci': lambda s: s.replace(' Capabilities: [80] Express (v2) Endpoint', ' Capabilities: <access denied>')}, 'PCIE_LINK_UNAVAILABLE'),
            # A BF4 function whose VPD serial is blank cannot confirm a physical
            # card count; the shared verbose capture carries both link and serial
            # data, so the identity guard is exercised through that same dump.
            ({'lspci': lambda s: s.replace(' [SN] Serial number: CARD-A', ' [SN] Serial number:')}, 'BF4_IDENTITY_UNAVAILABLE'),
        ]
        for project in ('neutrino', 'naboo'):
            for overrides, code in scenarios:
                with self.subTest(project=project, code=code):
                    result = self.run_fixture(project=project, overrides=overrides)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn('ISSUE|' + code, result.stdout)

    def test_lspci_collection_failure_fails_the_run(self):
        # P1-1: a failed lspci run must surface a structured COLLECTION_FAILED
        # issue and exit nonzero in every mode that depends on PCI data, instead
        # of silently skipping PCI checks and still reporting RESULT|PASS.
        def broken_lspci(_stub):
            return "echo 'lspci: cannot open /proc/bus/pci' >&2\nexit 3"
        for project in ('neutrino', 'naboo'):
            for mode in ('all', '-B'):
                with self.subTest(project=project, mode=mode):
                    result = self.run_fixture(project=project, mode=mode,
                                              overrides={'lspci': broken_lspci})
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn('ISSUE|COLLECTION_FAILED|', result.stdout)
                    self.assertNotIn('RESULT|PASS', result.stdout)
                    self.assertIn('RESULT|FAIL', result.stdout)

    def test_lspci_collection_failure_keeps_independent_checks_running(self):
        # P1-1 D/F: PCI collection failing must not stop checks that do not need
        # PCI data; CPU/DIMM/NVMe still execute and report their evidence.
        def broken_lspci(_stub):
            return "echo 'lspci: cannot open /proc/bus/pci' >&2\nexit 3"
        result = self.run_fixture(mode='all', overrides={'lspci': broken_lspci})
        self.assertIn('CHECK|DIMM|', result.stdout)
        self.assertIn('CHECK|NVMe|', result.stdout)
        self.assertIn('CHECK|CPU_ONLINE|', result.stdout)
        self.assertIn('ISSUE|COLLECTION_FAILED|PCI-inventory', result.stdout)

    def test_memory_ratio_boundary_and_invalid_config(self):
        # Sixteen 128 GiB modules = 2147483648 KiB; 50% is exact.
        for ratio, expected in [('0.5', 0), ('0.51', 1), ('nan', 1), ('0', 1)]:
            result = self.run_fixture(ratio=ratio, overrides={'cat': "printf 'MemTotal: 1073741824 kB\\n'"})
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

if __name__=='__main__':
    unittest.main()
