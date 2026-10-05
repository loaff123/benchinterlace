import copy
import json
from pathlib import Path
import tempfile
import unittest
from tests.fixtures import make_bundle, load_events, write_events, reseal, encode


class EligibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=make_bundle(Path(self.tmp.name)/'bundle',warmups=1)
    def tearDown(self): self.tmp.cleanup()
    def inspect(self):
        from benchinterlace.bundle import read_bundle
        from benchinterlace.eligibility import interpret
        return interpret(read_bundle(self.root))
    def change(self,fn):
        es=load_events(self.root); fn(es); write_events(self.root,es); reseal(self.root)
    def test_complete_full_vector(self):
        e=self.inspect(); self.assertEqual(e.status,'complete'); self.assertEqual(e.a,[100_000_000+20_000_000*i for i in range(8)]); self.assertEqual(e.counts['measured'],dict(planned=16,started=16,timed=16,validated=16,unstarted=0))
    def test_missing_seal_never_infers(self):
        (self.root/'seal.json').unlink(); e=self.inspect(); self.assertEqual(e.status,'incomplete'); self.assertIsNone(e.a); self.assertEqual(e.counts['measured']['timed'],16)
    def test_resealed_wrong_arm_rejected(self):
        self.change(lambda es: next(e for e in es if e['kind']=='slot_start')['data'].update(arm='A'))
        e=self.inspect(); self.assertEqual(e.status,'malformed'); self.assertIsNone(e.a)
    def test_zero_boolean_float_duration_rejected(self):
        for value in [0,True,1.0,2**63]:
            with self.subTest(value=value):
                self.change(lambda es: next(e for e in es if e['kind']=='slot_timing')['data'].update(elapsed_ns=value))
                self.assertNotEqual(self.inspect().status,'complete'); self.assertIsNone(self.inspect().a)
    def test_late_missing_capture_preserves_times(self):
        (self.root/'captures/000017.stdout').unlink(); e=self.inspect(); self.assertIsNone(e.a); self.assertEqual(e.counts['measured']['timed'],16)
    def test_late_final_fingerprint_failure_preserves_times(self):
        def alter(es):
            e=es[-2]['data']; e['status']='failed'; e['reasons']=[{'code':'input_changed'}]; e['files'][0]['sha256']='0'*64
            es[-1]['data']['state']='aborted'; es[-1]['data']['reasons']=[{'code':'input_changed'}]
        self.change(alter); e=self.inspect(); self.assertEqual(e.status,'failed'); self.assertIsNone(e.a); self.assertEqual(e.counts['measured']['timed'],16)
    def test_resealed_output_claim_not_authoritative(self):
        cap=self.root/'captures/000017.stdout'; cap.write_bytes(b'different')
        import hashlib
        def alter(es):
            e=[x for x in es if x['kind']=='slot_evidence'][-1]['data']['streams']['stdout']; e.update(retained_bytes=9,observed_bytes=9,sha256=hashlib.sha256(b'different').hexdigest())
        self.change(alter); self.assertEqual(self.inspect().status,'malformed')
    def test_extra_successful_record_not_filtered(self):
        self.change(lambda es: es.insert(-2,dict(es[4]))); self.assertEqual(self.inspect().status,'malformed')
    def test_crash_after_last_timer_preserves_timing(self):
        es=load_events(self.root); index=max(i for i,e in enumerate(es) if e['kind']=='slot_timing'); write_events(self.root,es[:index+1]); (self.root/'seal.json').unlink()
        # orphan captures are a crash artifact and prevent inference
        e=self.inspect(); self.assertIsNone(e.a); self.assertEqual(e.counts['measured']['timed'],16)
    def test_missing_paircheck_resealed_is_not_repaired(self):
        self.change(lambda es: es.pop(next(i for i,e in enumerate(es) if e['kind']=='pair_check'))); self.assertEqual(self.inspect().status,'malformed')
    def test_missing_all_declared_fingerprint_resealed(self):
        self.change(lambda es: next(e for e in es if e['kind']=='fingerprint_check')['data']['files'].pop()); self.assertEqual(self.inspect().status,'malformed')

    def test_incomplete_post_slot_fingerprint_does_not_validate_slot(self):
        from benchinterlace import report
        from benchinterlace.errors import ValidationError
        from unittest.mock import patch
        # Cover warmup and measured slots without discarding other valid facts.
        original = load_events(self.root)
        for slot, phase in ((0, 'warmup'), (2, 'measured'), (17, 'measured')):
            with self.subTest(slot=slot):
                events = copy.deepcopy(original)
                fingerprint = next(e['data'] for e in events
                    if e['kind']=='fingerprint_check' and e['data']['stage']=='post-slot'
                    and e['data']['slot']==slot)
                fingerprint['files'].pop()
                write_events(self.root, events); reseal(self.root)
                with patch.object(report, 'run_exact', side_effect=AssertionError('ineligible evidence reached worker')):
                    result = report.analyze(self.root)
                    self.assertEqual(result['evidence_status'], 'malformed')
                    self.assertEqual(result['inference_status'], 'withheld')
                    self.assertIsNone(result['test']); self.assertIsNone(result['descriptive'])
                    for name, planned in (('warmup', 2), ('measured', 16)):
                        self.assertEqual(result['counts'][name], dict(planned=planned,
                            started=planned, timed=planned, unstarted=0,
                            validated=planned-int(name==phase)))
                    saved = Path(self.tmp.name)/'report.json'
                    saved.write_bytes(encode(result))
                    self.assertEqual(report.verify(self.root, saved), result)
                    result['counts'][phase]['validated'] += 1
                    saved.write_bytes(encode(result))
                    with self.assertRaises(ValidationError): report.verify(self.root, saved)

    def test_empty_post_slot_fingerprints_with_late_failure_preserve_only_times(self):
        def alter(es):
            for event in es:
                if event['kind']=='fingerprint_check' and event['data']['stage']=='post-slot':
                    event['data']['files'] = []
            es[-2]['data'].update(status='failed', reasons=[{'code':'input_changed'}])
            es[-2]['data']['files'][0]['sha256'] = '0'*64
            es[-1]['data'].update(state='aborted', reasons=[{'code':'input_changed'}])
        self.change(alter)
        evidence = self.inspect()
        self.assertEqual(evidence.status, 'malformed')
        self.assertIsNone(evidence.a); self.assertIsNone(evidence.b)
        for phase, planned in (('warmup', 2), ('measured', 16)):
            self.assertEqual(evidence.counts[phase], dict(planned=planned,
                started=planned, timed=planned, validated=0, unstarted=0))

    def test_out_of_order_post_slot_fingerprint_does_not_validate_slot(self):
        def alter(es):
            next(e for e in es if e['kind']=='fingerprint_check'
                and e['data']['stage']=='post-slot')['data']['files'].reverse()
        self.change(alter)
        evidence = self.inspect()
        self.assertEqual(evidence.status, 'malformed')
        self.assertEqual(evidence.counts['warmup']['validated'], 1)
        self.assertEqual(evidence.counts['measured']['validated'], 16)

    def test_cross_phase_wrong_timing_slot_has_bounded_diagnostic(self):
        from benchinterlace.report import analyze
        def alter(es):
            timing=[e for e in es if e['kind']=='slot_timing'][2]
            timing['data']['slot']=0
        self.change(alter)
        r=analyze(self.root)
        self.assertEqual(r['evidence_status'],'malformed'); self.assertIsNone(r['counts']); self.assertIsNone(r['test'])

    def test_whole_run_budget_lower_bound(self):
        from benchinterlace.report import analyze
        from tests.fixtures import sha
        plan=json.loads((self.root/'plan.json').read_bytes()); plan['payload']['run_timeout_ns']=1_000_000_000
        plan['plan_id']='sha256:'+sha(encode(plan['payload'])); (self.root/'plan.json').write_bytes(encode(plan))
        es=load_events(self.root)
        for e in es: e['plan_id']=plan['plan_id']
        write_events(self.root,es); reseal(self.root)
        r=analyze(self.root)
        self.assertIsNone(r['test']); self.assertNotEqual(r['evidence_status'],'complete')

    def test_abort_reason_is_not_invented_interruption(self):
        es=load_events(self.root); es[-2]['data'].update(status='failed',reasons=[{'code':'input_changed'}]); es[-2]['data']['files'][0]['sha256']='0'*64
        es[-1]['data'].update(state='aborted',reasons=[{'code':'input_changed'}]); write_events(self.root,es); reseal(self.root)
        self.assertNotIn('interrupted',{x['code'] for x in self.inspect().reasons})

    def test_whole_run_budget_includes_prescribed_cleanup_grace(self):
        from benchinterlace.report import analyze
        from tests.fixtures import sha
        plan=json.loads((self.root/'plan.json').read_bytes()); plan['payload']['run_timeout_ns']=5_000_000_000
        plan['plan_id']='sha256:'+sha(encode(plan['payload'])); (self.root/'plan.json').write_bytes(encode(plan))
        es=load_events(self.root)
        for e in es: e['plan_id']=plan['plan_id']
        write_events(self.root,es); reseal(self.root)
        self.assertIsNone(analyze(self.root)['test'])

    def test_foreign_event_identity_nulls_phase_counts(self):
        from benchinterlace.report import analyze
        self.change(lambda es: es[4].update(plan_id='sha256:'+'a'*64))
        r=analyze(self.root); self.assertEqual(r['evidence_status'],'malformed'); self.assertIsNone(r['counts'])
