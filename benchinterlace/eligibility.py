"""Semantic replay; only a complete experiment exposes paired durations."""
from dataclasses import dataclass


@dataclass
class Evidence:
    plan: dict | None
    bundle_sha256: str | None
    status: str
    reasons: list
    counts: dict | None
    a: list | None = None
    b: list | None = None


def planned_slots(p):
    slots=[]
    for phase in ('warmup','measured'):
        for pair,order in enumerate(p['assignments'][phase]):
            for position,arm in enumerate(order):
                slots.append(dict(slot=len(slots),phase=phase,pair=pair,position=position,arm=arm))
    return slots


def interpret(bundle):
    reasons=list(bundle.reasons); malformed=bundle.malformed; failed=False; count_identity_uncertain=any(r['code'] in {'order_mismatch','duplicate_record','plan_mismatch'} for r in bundle.reasons)
    def reason(code,detail=''):
        r={'code':code}
        if detail: r['detail']=detail[:900]
        if r not in reasons and len(reasons)<100: reasons.append(r)
    def bad(code,detail):
        nonlocal malformed,count_identity_uncertain
        malformed=True; reason(code,detail)
        if code in {'order_mismatch','duplicate_record','plan_mismatch'}: count_identity_uncertain=True
    def fail(code,detail=''):
        nonlocal failed
        failed=True; reason(code,detail)
    def recorded(items):
        for item in items:
            fail(item['code'],item.get('detail',''))
    if bundle.plan is None:
        return Evidence(None,None,'malformed',reasons,None)
    plan=bundle.plan; p=plan['payload']; slots=planned_slots(p)
    counts={phase:dict(planned=2*p[phase+'_pairs'],started=0,timed=0,validated=0,unstarted=2*p[phase+'_pairs']) for phase in ('warmup','measured')}
    # Explicit protocol tokens; never sort, deduplicate, repair, or filter observations.
    tokens=[('run_start',None),('fingerprint_check',('pre-run',None))]
    for slot in slots:
        i=slot['slot']; tokens.extend([('fingerprint_check',('pre-slot',i)),('slot_start',slot),('slot_timing',i),('slot_evidence',i),('fingerprint_check',('post-slot',i))])
        if slot['position']==1: tokens.append(('pair_check',(slot['phase'],slot['pair'])))
    tokens.extend([('fingerprint_check',('post-run',None)),('run_end',None)])
    cursor=0; started={}; timed={}; evidence={}; post_good=set(); pair_good=set(); pair_seen=set(); capture_paths=set(); ended=False; final_good=False
    files={f['id']:f for f in p['files']}
    for event in bundle.events:
        k=event['kind']; d=event['data']
        if ended:
            bad('order_mismatch','Record after run_end'); continue
        expected=tokens[cursor] if cursor<len(tokens) else (None,None)
        early_final=k=='fingerprint_check' and d['stage']=='post-run' and expected!=('fingerprint_check',('post-run',None))
        abort_end=k=='run_end' and d['state']=='aborted'
        if early_final:
            if not failed and d['status']!='failed': bad('order_mismatch','Early post-run check without a recorded failure')
            cursor=len(tokens)-2; expected=tokens[cursor]
        if not abort_end and k!=expected[0]:
            bad('order_mismatch','Unexpected event kind at protocol boundary'); continue
        if k=='run_start':
            if cursor!=0 or d['expected_slots']!=len(slots): bad('order_mismatch','run_start slot count mismatch')
        elif k=='fingerprint_check':
            if (d['stage'],d['slot'])!=expected[1]: bad('order_mismatch','Fingerprint position mismatch')
            ids=[f['id'] for f in d['files']]
            # Malformed coverage cannot qualify a slot even when every supplied
            # file happens to match; preserved counts must reflect required checks.
            matches=ids==sorted(files)
            if not matches: bad('missing_record','Fingerprint must cover every declared file exactly once in ID order')
            for f in d['files']:
                declared=files.get(f['id'])
                if declared is None: bad('plan_mismatch','Unknown fingerprint file'); matches=False; continue
                if 'error_code' in f:
                    matches=False; fail(f['error_code']); continue
                if not f['stable_read']: matches=False; fail('unstable_read')
                if f['bytes']!=declared['bytes'] or f['sha256']!=declared['sha256']: matches=False; fail('input_changed')
            recorded(d['reasons'])
            if d['status']=='ok' and (not matches or d['reasons']): bad('invalid_schema','Successful fingerprint contradicts evidence')
            if d['status']=='failed':
                if not d['reasons'] and matches: bad('invalid_schema','Failed fingerprint has no failure fact')
                failed=True
            good=d['status']=='ok' and matches and not d['reasons']
            if d['stage']=='post-slot' and good: post_good.add(d['slot'])
            if d['stage']=='post-run': final_good=good
            if d['stage']=='pre-slot' and failed and good: bad('order_mismatch','New slot preparation after failure')
        elif k=='slot_start':
            if expected[1]!=d: bad('order_mismatch','Planned slot identity mismatch')
            i=d['slot']
            if i in started: bad('duplicate_record','Duplicate start')
            if failed: bad('order_mismatch','New slot after failure')
            if 0<=i<len(slots) and d==slots[i] and i not in started:
                started[i]=d; counts[d['phase']]['started']+=1; counts[d['phase']]['unstarted']-=1
        elif k=='slot_timing':
            i=d['slot']
            if expected[1]!=i or i not in started: bad('order_mismatch','Timing slot mismatch')
            if i in timed: bad('duplicate_record','Duplicate timing')
            timed[i]=d
            elapsed=d['elapsed_ns']; timeout=d['timeout_requested_ns']
            if i in started and elapsed is not None: counts[started[i]['phase']]['timed']+=1
            recorded(d['issues'])
            if sum(t['elapsed_ns'] or 0 for t in timed.values()) >= p['run_timeout_ns']:
                fail('run_timeout','Sum of nonoverlapping slot durations reaches the whole-run timeout')
            if elapsed is None:
                if d['elapsed_exceeded_timeout'] is not None: bad('invalid_schema','Unknown duration requires null exceeded flag')
                fail('invalid_duration','No usable duration')
            else:
                if d['elapsed_exceeded_timeout']!=(elapsed>=p['command_timeout_ns']): bad('invalid_schema','Timeout comparison flag contradicts duration')
                if elapsed<=0: fail('invalid_duration','Elapsed duration must be positive')
                if elapsed>=p['command_timeout_ns']: fail('command_timeout')
            if timeout is not None: fail('command_timeout','A timeout was requested')
            if d['exit_code']!=0: fail('nonzero_exit' if d['exit_code'] is not None else 'execution_outcome_unknown')
            if d['termination']!='exited': fail({'launch-failed':'launch_failed','timeout':'command_timeout','interrupted':'interrupted'}.get(d['termination'],'nonzero_exit'))
            if d['termination']=='exited' and (d['exit_code'] is None or d['exit_code']<0): bad('invalid_schema','Normal termination requires normal exit code')
            if d['termination']=='signal' and (d['exit_code'] is None or d['exit_code']>=0): bad('invalid_schema','Signal termination requires negative code')
            if d['termination']=='launch-failed' and (elapsed is not None or d['exit_code'] is not None): bad('invalid_schema','Launch failure invents an exit measurement')
        elif k=='slot_evidence':
            i=d['slot']
            if expected[1]!=i or i not in timed: bad('order_mismatch','Evidence slot mismatch')
            if i in evidence: bad('duplicate_record','Duplicate slot evidence')
            evidence[i]=d; recorded(d['issues'])
            if d['cleanup']!='completed': fail('cleanup_unconfirmed')
            streams_ok=True
            for stream,info in d['streams'].items():
                if info['state']=='unavailable': recorded([info['reason']]); streams_ok=False; continue
                path=f'captures/{i:06d}.{stream}'
                if info['path']!=path: bad('invalid_path','Non-prescribed capture path'); streams_ok=False
                capture_paths.add(path)
                actual=bundle.captures.get(path)
                if actual is None: reason('missing_record','Missing capture: '+path); streams_ok=False
                elif info['sha256']!=actual['sha256'] or info['retained_bytes']!=actual['bytes']: bad('hash_mismatch','Capture record differs from bytes'); streams_ok=False
                retained=info['retained_bytes']; observed=info['observed_bytes']
                if retained>p['capture_bytes_per_stream'] or observed<retained: bad('invalid_schema','Impossible capture byte counts'); streams_ok=False
                if info['truncated']!=(observed>retained): bad('invalid_schema','Truncation flag contradicts retained/observed counts'); streams_ok=False
                if not info['eof']: fail('capture_incomplete'); streams_ok=False
                if info['truncated']: fail('output_limit'); streams_ok=False
            mode=p['output_check']['mode']
            expected_output='pending-pair' if mode=='equal-within-pair' else ('not-requested' if mode=='none' else 'passed')
            if d['output_check']=='failed': fail('output_mismatch')
            elif d['output_check']!=expected_output: bad('invalid_schema','Output-check state contradicts frozen mode')
            if mode=='expected-sha256':
                out=d['streams']['stdout']; match=out['state']=='published' and out['sha256']==p['output_check']['sha256'] and out['retained_bytes']==p['output_check']['bytes'] and streams_ok
                if d['output_check']=='passed' and not match: bad('output_mismatch','Expected output claim is false')
            d_good=streams_ok and d['cleanup']=='completed' and not d['issues'] and d['output_check']!='failed'
            # Private derived fact, not a mutation of source evidence.
            evidence[i]=(d,d_good)
        elif k=='pair_check':
            identity=(d['phase'],d['pair'])
            if identity!=expected[1]: bad('order_mismatch','Pair-check identity mismatch')
            if identity in pair_seen: bad('duplicate_record','Duplicate pair check')
            pair_seen.add(identity); recorded(d['reasons'])
            indices=[s['slot'] for s in slots if (s['phase'],s['pair'])==identity]
            if len(indices)!=2 or any(i not in evidence for i in indices): bad('missing_record','Pair check lacks two slot-evidence records'); continue
            mode=p['output_check']['mode']; expected_status='not-requested' if mode=='none' else 'passed'
            if d['status']=='failed': fail('output_mismatch')
            elif d['status']!=expected_status: bad('invalid_schema','Pair-check status contradicts mode')
            match=all(evidence[i][1] for i in indices)
            if mode=='equal-within-pair':
                out=[evidence[i][0]['streams']['stdout'] for i in indices]
                match=match and all(v['state']=='published' for v in out)
                if match: match=(out[0]['sha256'],out[0]['retained_bytes'])==(out[1]['sha256'],out[1]['retained_bytes'])
            if d['status']=='passed' and not match: bad('output_mismatch','Pair success claim contradicts captures')
            if d['status']!= 'failed' and not d['reasons'] and match: pair_good.add(identity)
        elif k=='run_end':
            ended=True; recorded(d['reasons'])
            if d['completed_slots']!=len(evidence): bad('order_mismatch','completed_slots must count slot-evidence records')
            if d['not_run_slots']!=[i for i in range(len(slots)) if i not in started]: bad('order_mismatch','not_run_slots must list every unstarted slot')
            for phase,pair in {(s['phase'],s['pair']) for s in slots}:
                indices=[s['slot'] for s in slots if (s['phase'],s['pair'])==(phase,pair)]
                if all(i in evidence for i in indices) and (phase,pair) not in pair_seen: bad('missing_record','Two evidence records require a pair check')
            if d['state']=='complete':
                minimum_ns=sum(t['elapsed_ns'] or 0 for t in timed.values()) + 250_000_000*len(evidence)
                if minimum_ns >= p['run_timeout_ns']:
                    fail('run_timeout','Minimum elapsed plus required cleanup reaches whole-run timeout')
                if cursor!=len(tokens)-1 or failed or len(evidence)!=len(slots) or not final_good: bad('invalid_schema','Complete claim contradicts protocol or failure')
            else:
                if not failed: bad('invalid_schema','Aborted run has no failure reason')
                failed=True
        cursor+=1
    if set(bundle.captures)-capture_paths:
        reason('unexpected_artifact','Capture files have no committed evidence record')
        # Such a tail is incomplete evidence, including a crash after timing/publication.
    for i,d in timed.items():
        if i not in started or i not in evidence: continue
        good=(d['elapsed_ns'] is not None and 0<d['elapsed_ns']<p['command_timeout_ns'] and d['exit_code']==0 and d['termination']=='exited' and d['timeout_requested_ns'] is None and not d['issues'])
        s=started[i]
        if good and evidence[i][1] and i in post_good and (s['phase'],s['pair']) in pair_good: counts[s['phase']]['validated']+=1
    unresolved=set(started)-set(evidence)
    if unresolved: reason('execution_outcome_unknown','A started slot has no complete durable evidence')
    if not ended: reason('missing_record','No terminal run_end')
    if malformed: status='malformed'
    elif failed: status='failed'
    elif bundle.problems or not ended or unresolved or set(bundle.captures)-capture_paths: status='incomplete'
    elif any(c['validated']!=c['planned'] for c in counts.values()): status='incomplete'; reason('missing_record','Not all planned slots validated')
    else: status='complete'
    a=b=None
    if status=='complete':
        a=[]; b=[]
        for pair in range(p['measured_pairs']):
            by_arm={s['arm']:timed[s['slot']]['elapsed_ns'] for s in slots if s['phase']=='measured' and s['pair']==pair}
            a.append(by_arm['A']); b.append(by_arm['B'])
    return Evidence(plan,bundle.seal_sha256,status,reasons,None if count_identity_uncertain else counts,a,b)
