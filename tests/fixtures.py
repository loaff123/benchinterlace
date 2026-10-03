"""Original synthetic data only; never executed commands or measured timings."""
import hashlib
import json
from pathlib import Path


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'))+'\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def make_plan(n=8, warmups=0, alternative='two-sided', mode='equal-within-pair'):
    files = [{'id':'executable_a','path':'/synthetic/not-an-executable-a','bytes':0,'sha256':sha(b'')},
             {'id':'executable_b','path':'/synthetic/not-an-executable-b','bytes':0,'sha256':sha(b'')}]
    payload = dict(schema='benchinterlace.plan.v1', workload='Synthetic teaching fixture',
        cwd='/synthetic', commands={'A':{'argv':[files[0]['path']]},'B':{'argv':[files[1]['path']]}},
        measured_pairs=n,warmup_pairs=warmups,alternative=alternative,command_timeout_ns=30_000_000_000,
        run_timeout_ns=1_800_000_000_000,capture_bytes_per_stream=262144,capture_bytes_total=67108864,
        output_check={'mode':mode}, files=files, command_files={'A':'executable_a','B':'executable_b'},
        assignments={'method':'independent-os-bits-v1','measured':['AB' if i%2==0 else 'BA' for i in range(n)],'warmup':['BA']*warmups},
        runner_contract='linux-foreground-v1',timer_contract='spawn-to-observed-leader-exit-v1',
        capture_contract='bounded-pipes-v1',fingerprint_contract='declared-before-after-v1',generator_version='0.1.0-stage1')
    return {'plan_id':'sha256:'+sha(encode(payload)),'payload':payload}


def make_bundle(root, n=8, warmups=0, alternative='two-sided', mode='equal-within-pair'):
    root = Path(root)
    root.mkdir()
    (root/'events').mkdir()
    (root/'captures').mkdir()
    plan = make_plan(n,warmups,alternative,mode)
    (root/'plan.json').write_bytes(encode(plan))
    p=plan['payload']; events=[]
    def add(kind,data): events.append(dict(schema='benchinterlace.event.v1',seq=len(events),previous_sha256=None,plan_id=plan['plan_id'],kind=kind,data=data))
    def fp(stage,slot=None): add('fingerprint_check',dict(stage=stage,slot=slot,files=[dict(id=f['id'],bytes=f['bytes'],sha256=f['sha256'],stable_read=True) for f in p['files']],status='ok',reasons=[]))
    add('run_start',dict(runner_version='synthetic-fixture',python_version='synthetic',platform='linux',machine='synthetic',timer_name='synthetic-no-clock-used',timer_resolution_ns=1,expected_slots=2*(n+warmups)))
    fp('pre-run'); slot=0
    for phase in ['warmup','measured']:
        for pair,order in enumerate(p['assignments'][phase]):
            for position,arm in enumerate(order):
                fp('pre-slot',slot)
                add('slot_start',dict(slot=slot,phase=phase,pair=pair,position=position,arm=arm))
                duration=(100+20*pair+(10 if arm=='B' else 0))*1_000_000
                add('slot_timing',dict(slot=slot,elapsed_ns=duration,exit_code=0,termination='exited',timeout_requested_ns=None,elapsed_exceeded_timeout=False,issues=[]))
                streams={}
                for stream in ['stdout','stderr']:
                    data=b'synthetic output\n' if stream=='stdout' else b''
                    path=f'captures/{slot:06d}.{stream}'; (root/path).write_bytes(data)
                    streams[stream]=dict(state='published',path=path,retained_bytes=len(data),observed_bytes=len(data),sha256=sha(data),eof=True,truncated=False)
                add('slot_evidence',dict(slot=slot,streams=streams,output_check='not-requested' if mode=='none' else 'pending-pair',cleanup='completed',issues=[]))
                fp('post-slot',slot); slot+=1
            add('pair_check',dict(phase=phase,pair=pair,status='not-requested' if mode=='none' else 'passed',reasons=[]))
    fp('post-run'); add('run_end',dict(state='complete',completed_slots=slot,not_run_slots=[],reasons=[]))
    write_events(root,events)
    reseal(root)
    return root


def load_events(root):
    return [json.loads(x.read_bytes()) for x in sorted((Path(root)/'events').glob('*.json'))]


def write_events(root,events):
    root=Path(root)
    for f in (root/'events').iterdir(): f.unlink()
    previous=None
    for i,e in enumerate(events):
        e['seq']=i; e['previous_sha256']=previous
        raw=encode(e); (root/'events'/f'{i:06d}.json').write_bytes(raw); previous=sha(raw)


def reseal(root):
    root=Path(root); plan=json.loads((root/'plan.json').read_bytes()); files=[]
    for f in sorted([root/'plan.json',*(root/'events').glob('*.json'),*(root/'captures').iterdir()],key=lambda x:x.relative_to(root).as_posix()):
        raw=f.read_bytes(); files.append(dict(path=f.relative_to(root).as_posix(),bytes=len(raw),sha256=sha(raw)))
    last=sorted((root/'events').glob('*.json'))
    seal=dict(schema='benchinterlace.seal.v1',plan_id=plan['plan_id'],last_event_sha256=sha(last[-1].read_bytes()) if last else sha(b''),files=files)
    (root/'seal.json').write_bytes(encode(seal))
