"""Run vera_rack.sh against PATH stubs, never the host's hardware tools."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]
SHELL=os.environ.get('VERA_TEST_SHELL') or shutil.which('bash')

@unittest.skipUnless(SHELL,'Set VERA_TEST_SHELL to a Bash executable')
class HardwareTests(unittest.TestCase):
    def run_fixture(self, dimms=16, bf4='BlueField-4', downgrade=False):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            tools={
              'dmidecode':f'''case "$*" in
                '-t processor') printf 'Status: Populated, Enabled\\nStatus: Populated, Enabled\\n';;
                '-t memory') for ((i=1;i<={dimms};i++)); do printf 'Memory Device\\n Size: 128 GB\\n'; done; printf 'Memory Device\\n Size: No Module Installed\\n';;
                *) echo 'Version: example';; esac''',
              'nvme':"printf '/dev/nvme0n1 disk0\\n/dev/nvme0n2 namespace2\\n/dev/nvme1n1 disk1\\n'",
              'mst':f'''for ((i=1;i<=22;i++)); do echo "Vera(rev:0) /dev/mst/mt12183_pciconf$i 0001:01:00.0"; done
                        echo '{bf4}(rev:0) /dev/mst/dpu 0000:02:00.0' ''',
              'lspci':f'''if [[ "$*" == -Dvv ]]; then
                    printf '0000:01:00.0 Controller\\n LnkSta: Speed 16GT/s, Width x8 {'(downgraded)' if downgrade else ''}\\n'
                  else
                    for ((i=1;i<=20;i++)); do printf '0000:01:00.0 PCI bridge [0604]: NVIDIA bridge [10de:2f95]\\n'; done
                    echo '0000:02:00.0 USB controller [0c03]: controller [1234:5678]'
                    echo '0000:03:00.0 PCI bridge [0604]: ASPEED AST1150 [1234:9876]'
                  fi''',
              'ipmitool':"echo 'Firmware Revision: example'"}
            for name,content in tools.items():
                file=root/name
                file.write_text('#!/usr/bin/env bash\n'+content+'\n',encoding='utf-8',newline='\n')
                file.chmod(0o755)
            # Git for Windows sh is Bash but env bash may not exist. Use sh
            # shebang stubs; they use only Bash-compatible Git sh syntax.
            for name in tools:
                file=root/name
                file.write_text(file.read_text().replace('/usr/bin/env bash','/usr/bin/env sh'),encoding='utf-8',newline='\n')
            env={**os.environ,'PATH':str(root)+os.pathsep+str(Path(SHELL).parent)+os.pathsep+os.environ.get('PATH','')}
            result=subprocess.run([SHELL,str(BASE/'vera_rack.sh')],env=env,capture_output=True,text=True,timeout=45)
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

    def test_downgrade_is_failure_with_bdf(self):
        result=self.run_fixture(downgrade=True)
        self.assertEqual(result.returncode,1,result.stdout+result.stderr)
        self.assertIn('ISSUE|PCIE_DOWNGRADE|0000:01:00.0',result.stdout)

if __name__=='__main__':
    unittest.main()
