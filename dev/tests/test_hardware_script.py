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
    def run_fixture(self, dimms=16, bf4='BlueField-4', downgrade=False, functions=2, serials=None, endpoint=True, unavailable=False, project='neutrino'):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            serials = ['CARD-A'] * functions if serials is None else serials
            identities = '\n'.join(f"0000:0{i+4}:00.0 Ethernet controller: Mellanox {bf4}\n Capabilities: [54] Vital Product Data\n [SN] Serial number: {serial}" for i, serial in enumerate(serials))
            pci_functions = '\n'.join(f"0000:0{i+4}:00.0 Ethernet controller [0200]: Mellanox {bf4} [15b3:a2dc]" for i in range(functions))
            tools={
              'dmidecode':f'''case "$*" in
                '-t processor') printf 'Status: Populated, Enabled\\nStatus: Populated, Enabled\\n';;
                '-t memory') i=1; while [ "$i" -le {dimms} ]; do printf 'Memory Device\\n Size: 128 GB\\n'; i=$((i+1)); done; printf 'Memory Device\\n Size: No Module Installed\\n';;
                *) echo 'Version: example';; esac''',
              'nvme':"printf '/dev/nvme0n1 disk0\\n/dev/nvme0n2 namespace2\\n/dev/nvme1n1 disk1\\n'",
              'mst':f'''i=1; while [ "$i" -le 22 ]; do echo "Vera(rev:0) /dev/mst/mt12183_pciconf$i 0001:01:00.0"; i=$((i+1)); done
                        echo '{bf4}(rev:0) /dev/mst/dpu 0000:02:00.0' ''',
              'lspci':f'''case "$1" in
                    -Dvvv) printf '%s\\n' '{identities}';;
                    -Dvv) printf '0000:01:00.0 Controller\\n Capabilities: [80] Express (v2) {'Endpoint' if endpoint else 'Root Port'}\\n LnkSta: Speed {'unknown, Width x0' if unavailable else '16GT/s, Width x8'} {'(downgraded)' if downgrade else ''}\\n';;
                    *) i=1; while [ "$i" -le 20 ]; do printf '0000:01:00.0 PCI bridge [0604]: NVIDIA bridge [10de:2f95]\\n'; i=$((i+1)); done
                       printf '%s\\n' '{pci_functions}'
                       echo '0000:02:00.0 USB controller [0c03]: controller [1234:5678]'
                       echo '0000:03:00.0 PCI bridge [0604]: ASPEED AST1150 [1234:9876]';;
                  esac''',
              'ipmitool':"echo 'Firmware Revision: example'"}
            # POSIX sh stubs so the harness runs under both dash and Git Bash.
            for name,content in tools.items():
                file=root/name
                file.write_text('#!/usr/bin/env sh\n'+content+'\n',encoding='utf-8',newline='\n')
                file.chmod(0o755)
            env={**os.environ,'PATH':str(root)+os.pathsep+str(Path(SHELL).parent)+os.pathsep+os.environ.get('PATH','')}
            result=subprocess.run([SHELL,str(BASE/f'{project}_config.sh')],env=env,capture_output=True,text=True,timeout=45,check=False)
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

if __name__=='__main__':
    unittest.main()
