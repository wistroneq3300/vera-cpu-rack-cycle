"""Generate synthetic review data without constructing any hardware transport."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from cycle_core import *
from cycle_engine import new_record
from cycle_report import write_reports

def build(output):
    nodes=[]
    for index in range(1,4):
        t=Target('L105-21R',f'n{index}',f'192.0.2.{index*2-1}',f'192.0.2.{index*2}',f'example-bmc-{index}',f'example-os-{index}')
        node=dict(key=t.key,target=t.__dict__,blocked=[],active=True,completed=3,stop_reason='',pre=new_record('PRE'),loops=[])
        pre_keys=set()
        for number in range(4):
            record=node['pre'] if number==0 else new_record(f'LOOP {number}')
            if number:
                record.update(loop=number,post_complete=True)
                node['loops'].append(record)
                record['action']=[dict(command='ipmitool power cycle',role='os',state='SENT',code=0)]
                record['recovery']=dict(boot_changed=True,old_boot_id=f'example-boot-{number-1}',new_boot_id=f'example-boot-{number}',attempts=8)
            record['identities']={'bmc':dict(hostname=t.bmc_hostname),'os':dict(hostname=t.os_hostname)}
            record['issues']=[issue('BF4_MISSING','BF4','Expected at least 1; detected 0')]
            if index==2 and number>=2:
                record['issues'].append(issue('PCIE_DOWNGRADE','000c:80:00.0','LnkSta: Speed 16GT/s (downgraded), Width x8'))
            if index==3 and number==1:
                record['issues'].append(issue('SENSOR_RECOVERED','Temp_CPU1','One missing sensor row returned on immediate reread','WARN'))
            if number==0:
                # PRE is the baseline; capture its (code, component) pairs.
                pre_keys={(i['code'], i['component']) for i in record['issues']}
            folder=Path(t.key)/(f'loop{number:04d}' if number else '')
            prefix='post' if number else 'pre'
            path=(folder/f'{prefix}_hardware.txt').as_posix()
            for item in record['issues']:
                item['evidence']=path
            classify_against_pre(record['issues'], set() if number==0 else pre_keys)
            record.update(status=health(record['issues']),started=f'2026-09-29T08:{number*10:02d}:00+00:00',finished=f'2026-09-29T08:{number*10+8:02d}:00+00:00')
            record['evidence']=[path]
            record['sel_review']='REVIEW REQUIRED: compare cumulative BMC SEL with expected boot events.'
            atomic_write(output/path,'SYNTHETIC EXAMPLE — no hardware operated\n'+ '\n'.join(i['detail'] for i in record['issues'])+'\n')
        nodes.append(node)
    campaign=dict(run_id='neutrino_DEMO_20260929_160000',project='neutrino',started='2026-09-29T08:00:00+00:00',finished='2026-09-29T08:38:00+00:00',
                  state='COMPLETE',stop_reason='All 3 requested loops completed on 3 approved nodes.',cycle_mode='power_cycle',channel='inband',limits=dict(loops=3,hours=0),
                  script_sha256=digest((Path(__file__).resolve().parents[2]/'vera_rack.sh').read_bytes()),nodes=nodes,synthetic=True)
    write_reports(output,campaign)

if __name__=='__main__':
    build(Path(sys.argv[1]) if len(sys.argv)>1 else Path('test-results/demo'))
