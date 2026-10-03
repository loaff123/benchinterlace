import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from benchinterlace.canonical import canonical_bytes
from benchinterlace.plan import make_plan
from benchinterlace.report import analyze
from benchinterlace.runner_linux import run_plan

HELPER=Path(__file__).with_name('owned_helper.py').resolve()

def owned_spec(root, mode='normal', args=(), **changes):
    value=dict(schema='benchinterlace.spec.v1',workload='Original owned helper test',cwd=str(root),
        commands={a:{'argv':[sys.executable,str(HELPER),mode,*args]} for a in ('A','B')},
        files=[{'id':'helper','path':str(HELPER)}], measured_pairs=2,warmup_pairs=0,
        alternative='two-sided',command_timeout_ns=2_000_000_000,run_timeout_ns=10_000_000_000,
        output_check={'mode':'equal-within-pair'})
    value.update(changes); return value

@unittest.skipUnless(sys.platform=='linux','Linux runner')
class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
    def tearDown(self): self.temp.cleanup()
    def plan(self,**kw):
        path=self.root/'plan.json'; path.write_bytes(canonical_bytes(make_plan(owned_spec(self.root,**kw)))); return path
    def test_end_to_end_cli(self):
        spec=self.root/'spec.json'; spec.write_text(json.dumps(owned_spec(self.root)))
        plan=self.root/'plan.json'; bundle=self.root/'run'; report=self.root/'report'
        for args in [('plan','--spec',spec,'--out',plan),('run','--plan',plan,'--out',bundle),
                     ('analyze',bundle,'--out',report),('verify',bundle,'--report',report/'report.json')]:
            result=subprocess.run([sys.executable,'-m','benchinterlace',*map(str,args)],capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(analyze(bundle)['evidence_status'],'complete')
        self.assertEqual(run_plan(plan,bundle),2)

    def test_all_checks_mode_and_warmups(self):
        for mode in ('none','expected-sha256'):
            import hashlib
            check={'mode':mode}
            if mode!='none': check.update(sha256=hashlib.sha256(b'owned payload\n').hexdigest(),bytes=14)
            plan=self.root/(mode+'.json'); plan.write_bytes(canonical_bytes(make_plan(owned_spec(self.root,warmup_pairs=1,output_check=check))))
            bundle=self.root/mode
            self.assertEqual(run_plan(plan,bundle),0)
            report=analyze(bundle); self.assertEqual(report['evidence_status'],'complete',report['reasons'])
            self.assertEqual(report['counts']['warmup']['validated'],2)

    def test_no_next_slot_after_nonzero_timeout_or_cap(self):
        for mode,args,options in [('nonzero',(),{}),('sleep',('1',),{'command_timeout_ns':50_000_000}),
                                  ('flood',(),{'capture_bytes_per_stream':1024})]:
            plan=self.root/(mode+'.json'); plan.write_bytes(canonical_bytes(make_plan(owned_spec(self.root,mode,args,**options))))
            bundle=self.root/mode
            self.assertEqual(run_plan(plan,bundle),3)
            report=analyze(bundle)
            self.assertEqual(report['evidence_status'],'failed',report['reasons'])
            self.assertEqual(report['counts']['measured']['started'],1)
            self.assertEqual(report['counts']['measured']['timed'],1)
            self.assertIsNone(report['test'])

    def test_changed_plan_and_input_prevent_launch(self):
        plan=self.plan()
        payload=json.loads(plan.read_bytes())
        Path(payload['payload']['files'][0]['path']) # Analysis must never follow these paths.
        from benchinterlace import runner_linux
        with patch.object(runner_linux,'collect_slot',side_effect=AssertionError('must not launch')):
            with patch.object(runner_linux,'check_plan_copies',side_effect=runner_linux.ValidationError('plan_changed','injected')):
                self.assertEqual(run_plan(plan,self.root/'run'),3)
        report=analyze(self.root/'run'); self.assertIsNone(report['test'])
        self.assertEqual(report['counts']['measured']['started'],0)

    def test_late_capture_failure_preserves_timing(self):
        plan=self.plan()
        from benchinterlace.journal import Journal
        with patch.object(Journal,'capture',side_effect=OSError('injected full disk')):
            self.assertEqual(run_plan(plan,self.root/'run'),5)
        report=analyze(self.root/'run')
        self.assertEqual(report['counts']['measured']['timed'],1)
        self.assertIsNone(report['test'])

    def test_read_only_verification(self):
        from benchinterlace.report import verify
        plan=self.plan(); bundle=self.root/'run'; self.assertEqual(run_plan(plan,bundle),0)
        before={str(p.relative_to(bundle)):(p.read_bytes(),p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in bundle.rglob('*') if p.is_file()}
        verify(bundle)
        after={str(p.relative_to(bundle)):(p.read_bytes(),p.stat().st_mtime_ns,p.stat().st_ctime_ns) for p in bundle.rglob('*') if p.is_file()}
        self.assertEqual(before,after)
    def test_after_final_timer_input_change_preserves_all_timings(self):
        from benchinterlace.journal import Journal
        declared=self.root/'declared.txt'; declared.write_bytes(b'original')
        spec=owned_spec(self.root); spec['files'].append({'id':'declared','path':str(declared)})
        plan=self.root/'plan.json'; plan.write_bytes(canonical_bytes(make_plan(spec)))
        original=Journal.append
        def mutate(journal,kind,data):
            result=original(journal,kind,data)
            if kind=='slot_timing' and data['slot']==3:
                declared.write_bytes(b'changed')
            return result
        with patch.object(Journal,'append',mutate):
            self.assertEqual(run_plan(plan,self.root/'run'),3)
        report=analyze(self.root/'run')
        self.assertEqual(report['evidence_status'],'failed',report['reasons'])
        self.assertEqual(report['counts']['measured']['timed'],4)
        self.assertIsNone(report['test'])
        self.assertIn('input_changed',{r['code'] for r in report['reasons']})

    def test_after_final_timer_output_mismatch_preserves_all_timings(self):
        from benchinterlace.journal import Journal
        plan=self.plan(); original=Journal.capture
        def replace(journal,slot,stream,data):
            if slot==3 and stream=='stdout': data=b'different retained output'
            return original(journal,slot,stream,data)
        # This injected corruption must be rejected, never repaired into inference.
        with patch.object(Journal,'capture',replace):
            self.assertEqual(run_plan(plan,self.root/'run'),3)
        report=analyze(self.root/'run')
        self.assertEqual(report['counts']['measured']['timed'],4)
        self.assertIsNone(report['test'])


class LateReasonTests(unittest.TestCase):
    def test_late_timeout_is_not_invented_input_mutation(self):
        from tests.fixtures import make_bundle,load_events,write_events,reseal
        with tempfile.TemporaryDirectory() as tmp:
            root=make_bundle(Path(tmp)/'bundle')
            events=load_events(root)
            events[-2]['data']['status']='failed'
            events[-2]['data']['reasons']=[{'code':'run_timeout'}]
            events[-1]['data']['state']='aborted'
            events[-1]['data']['reasons']=[{'code':'run_timeout'}]
            write_events(root,events); reseal(root)
            report=analyze(root)
            codes={r['code'] for r in report['reasons']}
            self.assertIn('run_timeout',codes)
            self.assertNotIn('input_changed',codes)
            self.assertIsNone(report['test'])

    def test_timeout_file_record_does_not_invent_changed_input(self):
        from tests.fixtures import make_bundle,load_events,write_events,reseal
        with tempfile.TemporaryDirectory() as tmp:
            root=make_bundle(Path(tmp)/'bundle')
            events=load_events(root)
            final=events[-2]['data']; final['status']='failed'
            final['files']=[{'id':f['id'],'error_code':'run_timeout'} for f in final['files']]
            events[-1]['data']['state']='aborted'
            events[-1]['data']['reasons']=[{'code':'run_timeout'}]
            write_events(root,events); reseal(root)
            report=analyze(root)
            codes={r['code'] for r in report['reasons']}
            self.assertIn('run_timeout',codes)
            self.assertNotIn('input_changed',codes)
