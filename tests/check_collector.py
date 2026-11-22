import json
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

here = Path(__file__).resolve().parent
src = Path(sys.argv[1]).resolve() if len(sys.argv)>1 else here.parent/'src'/'Collector.ps1'
scratch = tempfile.TemporaryDirectory(prefix='usb-audit-tests-')
work = Path(scratch.name)
def frame(at, state, **kw): return dict(at=at, inventory=state, **kw)
def run(name, frames):
    folder=work/name
    folder.mkdir(exist_ok=True)
    case=folder/'scenario.json'
    case.write_text(json.dumps(frames), encoding='utf-8')
    subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',
        str(here/'run_collector.ps1'),'-Source',str(src),'-Scenario',str(case),'-FixtureRoot',str(folder)], check=True)
    log=folder/'LocalUsbAudit'/'Data'/'Active'/'events.jsonl'
    return [json.loads(line) for line in log.read_text('utf-8-sig').splitlines() if line.strip()]
def transitions(rows): return [r['type'] for r in rows if r['type'] in ('connect','disconnect','end_unknown')]
def reason(rows, kind, source):
    matches=[r for r in rows if r['type']==kind and r.get('endSource')==source]
    assert len(matches)==1, [(r['type'],r.get('endSource')) for r in rows]
    return matches[0]
def ss(r, field):
    return (datetime.fromisoformat(r[field]) - datetime.fromisoformat('2026-11-22T06:30:00+00:00')).total_seconds()
p='present'; a='absent'; e='error'
removed=[frame(0,p),frame(4,p),frame(8,a,probe=7),frame(12,a,probe=7),frame(16,a,probe=9)]
rows=run('abrupt',removed+[frame(20,p),frame(24,p)])
assert transitions(rows)==['connect','disconnect','connect'],transitions(rows)
r=reason(rows,'disconnect','inventory')
assert ss(r,'lastSeen')==4 and ss(r,'time')==8,r
assert rows[0]['type']=='status' and len({r['session'] for r in rows if r['type']=='connect'})==2
assert (work/'abrupt'/'probes.txt').read_text().splitlines()==['8 deferred','12 False True','16 False False']
rows=run('transient',[frame(0,p),frame(4,a),frame(8,p),frame(12,p)])
assert transitions(rows)==['connect'],transitions(rows)
rows=run('wmi',[frame(0,p),frame(4,p),frame(8,a,events=[{'kind':3,'at':7}])])
assert transitions(rows)==['connect','disconnect']
assert ss(reason(rows,'disconnect','volumeEvent'),'time')==7
rows=run('wmi-fast',[frame(0,p),frame(4,p),frame(8,p,events=[{'kind':3,'at':6},{'kind':2,'at':7}])])
assert transitions(rows)==['connect','disconnect','connect']
rows=run('wmi-early',[frame(0,p),frame(4,p),frame(8,'unmounted',events=[{'kind':3,'at':7}]),
    frame(12,'unmounted'),frame(16,a),frame(20,a)])
assert transitions(rows)==['connect','disconnect'],transitions(rows)
assert ss(reason(rows,'disconnect','volumeEvent'),'time')==7
rows=run('wmi-expired',[frame(0,p),frame(4,p),frame(8,'unmounted',events=[{'kind':3,'at':7}]),
    frame(12,'unmounted'),frame(16,'unmounted'),frame(20,'unmounted'),frame(24,'unmounted'),frame(28,a),frame(32,a)])
assert transitions(rows)==['connect','disconnect'],transitions(rows)
assert ss(reason(rows,'disconnect','inventory'),'time')==28
rows=run('quick-return',[frame(0,p),frame(4,p),frame(8,a),frame(12,p,events=[{'kind':2,'at':10}])])
assert transitions(rows)==['connect','disconnect','connect'],transitions(rows)
rows=run('errors',[frame(0,p),frame(4,p),frame(8,e),frame(12,e),frame(16,p)])
assert transitions(rows)==['connect'],transitions(rows)
rows=run('gap',[frame(0,p),frame(4,p),frame(8,e),frame(44,e),frame(48,a),frame(52,a)])
assert transitions(rows)==['connect','end_unknown'],transitions(rows)
reason(rows,'end_unknown','observationGap')
rows=run('restart',[frame(0,p)])
assert transitions(rows)==['connect']
rows=run('restart',[frame(60,a),frame(64,a)])
assert transitions(rows)==['connect','end_unknown']
reason(rows,'end_unknown','collectorRestart')
rows=run('overrun',[frame(0,p),frame(4,p),frame(8,p,events=[{'kind':2,'at':7}]*129),frame(12,p)])
assert transitions(rows)==['connect','end_unknown','connect'],transitions(rows)
reason(rows,'end_unknown','queueOverflow')
print('Passed real collector loop in Windows PowerShell: abrupt removal, time interval, delayed file binding, reconnect, debounce, WMI removal/reinsert, failed inventory, observation gap and checkpoint restart.')

scratch.cleanup()
