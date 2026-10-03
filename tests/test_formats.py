"""Original format tests; synthetic objects never describe a measured run."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import unittest


class FormatTests(unittest.TestCase):
    def setUp(self):
        try:
            self.c = importlib.import_module('benchinterlace.canonical')
            self.s = importlib.import_module('benchinterlace.schema')
            self.e = importlib.import_module('benchinterlace.errors').ValidationError
        except ModuleNotFoundError as exc:
            self.fail('strict format implementation is missing: ' + str(exc))

    def spec(self):
        return {'schema':'benchinterlace.spec.v1','workload':'synthetic λ',
                'cwd':'/absent/work','commands':{'A':{'argv':['/absent/a','']},
                'B':{'argv':['/absent/b']}},'files':[], 'measured_pairs':2,
                'warmup_pairs':0,'alternative':'two-sided',
                'command_timeout_ns':1000000,'run_timeout_ns':1000000000,
                'output_check':{'mode':'equal-within-pair'}}

    def plan(self):
        p = self.spec(); p['schema'] = 'benchinterlace.plan.v1'
        p.update(capture_bytes_per_stream=262144, capture_bytes_total=67108864,
                 files=[{'id':'executable_a','path':'/absent/a','bytes':0,'sha256':'0'*64},
                        {'id':'executable_b','path':'/absent/b','bytes':1,'sha256':'1'*64}],
                 command_files={'A':'executable_a','B':'executable_b'},
                 assignments={'method':'independent-os-bits-v1','measured':['AB','BA'],'warmup':[]},
                 runner_contract='linux-foreground-v1',
                 timer_contract='spawn-to-observed-leader-exit-v1',
                 capture_contract='bounded-pipes-v1',
                 fingerprint_contract='declared-before-after-v1',
                 generator_version='0.1.0-stage1')
        return self.reseal({'plan_id':'', 'payload':p})

    def reseal(self,p):
        p['plan_id'] = 'sha256:' + self.c.digest(self.c.canonical_bytes(p['payload']))
        return p

    def event(self,kind,data):
        return {'schema':'benchinterlace.event.v1','seq':0,'previous_sha256':None,
                'plan_id':'sha256:'+'0'*64,'kind':kind,'data':data}

    def report(self):
        return {'schema':'benchinterlace.report.v1','plan_id':None,'bundle_sha256':None,
                'analysis_version':'0.1.0-stage1','evidence_status':'malformed',
                'inference_status':'withheld','reasons':[{'code':'invalid_schema'}],
                'warnings':[], 'counts':None,'descriptive':None,'test':None}

    def test_canonical_encoding_and_hash(self):
        value={'z':'λ\n','a':[True,None,-2]}
        raw=b'{"a":[true,null,-2],"z":"\\u03bb\\n"}\n'
        self.assertEqual(self.c.canonical_bytes(value),raw)
        self.assertEqual(self.c.digest(raw),hashlib.sha256(raw).hexdigest())
        self.assertEqual(self.c.parse_json(raw,1024,canonical=True),value)
        self.assertEqual(self.c.parse_json(b' { "a": 2 } ',1024),{'a':2})

    def test_json_rejects_duplicate_numbers_and_bad_unicode(self):
        for raw in [b'{"a":1,"a":2}',b'1.0',b'1e3',b'NaN',b'Infinity',
                    b'"\\ud800"',b'"\\udfff"',b'"\\u0000"',b'"\xff"',
                    b'\xef\xbb\xbf{}',b'{}garbage',b'1'*100]:
            with self.subTest(raw=raw),self.assertRaises(self.e):
                self.c.parse_json(raw,1024)
        for value in [1.0,float('nan'),'\ud800','\x00',{'a':object()}, {1:'x'}]:
            with self.subTest(value=repr(value)),self.assertRaises(self.e):
                self.c.canonical_bytes(value)

    def test_json_size_depth_and_canonical_enforcement(self):
        with self.assertRaises(self.e): self.c.parse_json(b'{}',1)
        for raw in [b'{}',b'{}\n\n',b'{"b":1,"a":2}\n',b'"\\u0061"\n']:
            with self.subTest(raw=raw),self.assertRaises(self.e):
                self.c.parse_json(raw,1024,canonical=True)
        raw=b'['*12+b'0'+b']'*12
        self.c.parse_json(raw,1024)
        with self.assertRaises(self.e): self.c.parse_json(b'['+raw+b']',1024)
        with self.assertRaises(self.e): self.c.canonical_bytes([[[[[[[[[[[[[0]]]]]]]]]]]]])

    def test_error_contract(self):
        error=self.e('invalid_schema','bounded detail')
        self.assertEqual(error.code,'invalid_schema')
        self.assertEqual(error.detail,'bounded detail')
        self.assertIn('bounded detail',str(error))

    def test_spec_exact_inventory_types_and_optional_defaults(self):
        s=self.spec(); self.s.validate_spec(s)
        self.assertNotIn('capture_bytes_per_stream',s)
        for name,value in [('measured_pairs',True),('measured_pairs',2.0),
                ('measured_pairs',1),('measured_pairs',41),('warmup_pairs',11),
                ('command_timeout_ns',999999),('run_timeout_ns',86400000000001),
                ('capture_bytes_per_stream',0),('capture_bytes_total',268435457),
                ('workload','λ'*65),('cwd','relative')]:
            bad=copy.deepcopy(s);bad[name]=value
            with self.subTest(name=name,value=value),self.assertRaises(self.e): self.s.validate_spec(bad)
        for bad in [dict(s,extra=1), {k:v for k,v in s.items() if k!='files'}]:
            with self.assertRaises(self.e): self.s.validate_spec(bad)
        for mutate in [lambda x:x['commands']['A'].update(extra=1),
                       lambda x:x['commands']['A'].update(argv=[]),
                       lambda x:x['commands']['A'].update(argv=['a']),
                       lambda x:x['commands']['A'].update(argv=['/a']+['x'*4096]*4),
                       lambda x:x.update(files=[{'id':'executable_a','path':'/a'}]),
                       lambda x:x.update(files=[{'id':'x','path':'/a'},{'id':'x','path':'/b'}])]:
            bad=copy.deepcopy(s);mutate(bad)
            with self.assertRaises(self.e): self.s.validate_spec(bad)

    def test_output_check_union(self):
        for check in [{'mode':'none'},{'mode':'equal-within-pair'},
                      {'mode':'expected-sha256','sha256':'a'*64,'bytes':0}]:
            self.s.validate_spec(dict(self.spec(),output_check=check))
        for check in [{'mode':'none','bytes':0},{'mode':'expected-sha256','sha256':'A'*64,'bytes':0},
                      {'mode':'expected-sha256','sha256':'a'*64,'bytes':262145}]:
            with self.assertRaises(self.e): self.s.validate_spec(dict(self.spec(),output_check=check))

    def test_plan_pure_paths_identities_and_normalization(self):
        p=self.plan();self.s.validate_plan(p)
        for mutate in [lambda x:x['payload']['assignments']['measured'].append('AB'),
                       lambda x:x['payload']['command_files'].update(A='missing'),
                       lambda x:x['payload']['commands']['A'].update(argv=['/wrong']),
                       lambda x:x['payload']['files'].reverse(),
                       lambda x:x['payload']['files'][0].update(path='/absent/../a'),
                       lambda x:x['payload']['files'].append(dict(x['payload']['files'][0])),
                       lambda x:x['payload']['files'][0].update(bytes=1073741825),
                       lambda x:x['payload']['files'][1].update(path='/absent/a'),
                       lambda x:x['payload']['files'][0].update(id='arbitrary')]:
            bad=copy.deepcopy(p);mutate(bad);self.reseal(bad)
            with self.subTest(plan=bad),self.assertRaises(self.e): self.s.validate_plan(bad)
        bad=copy.deepcopy(p);bad['payload']['workload']='changed'
        with self.assertRaises(self.e): self.s.validate_plan(bad)
        same=copy.deepcopy(p);same['payload']['files'].pop()
        same['payload']['command_files']['B']='executable_a'
        same['payload']['commands']['B']['argv'][0]='/absent/a'
        self.s.validate_plan(self.reseal(same))

    def test_all_event_variants_and_exact_nested_inventories(self):
        reason={'code':'capture_io','detail':'original synthetic error'}
        stream={'state':'published','path':'captures/000000.stdout','retained_bytes':0,
                'observed_bytes':0,'sha256':'0'*64,'eof':True,'truncated':False}
        samples=[('run_start',{'runner_version':'0.1.0-stage1','python_version':'3.11.0',
                    'platform':'linux','machine':'x86_64','timer_name':'clock_gettime(CLOCK_MONOTONIC)',
                    'timer_resolution_ns':1,'expected_slots':4}),
                 ('fingerprint_check',{'stage':'pre-run','slot':None,'files':[
                    {'id':'executable_a','bytes':0,'sha256':'0'*64,'stable_read':True},
                    {'id':'executable_b','error_code':'capture_io'}],'status':'failed','reasons':[reason]}),
                 ('slot_start',{'slot':0,'phase':'measured','pair':0,'position':0,'arm':'A'}),
                 ('slot_timing',{'slot':0,'elapsed_ns':0,'exit_code':0,'termination':'exited',
                    'timeout_requested_ns':None,'elapsed_exceeded_timeout':False,'issues':[]}),
                 ('slot_evidence',{'slot':0,'streams':{'stdout':stream,
                    'stderr':{'state':'unavailable','reason':reason}},'output_check':'failed',
                    'cleanup':'unconfirmed','issues':[reason]}),
                 ('pair_check',{'phase':'warmup','pair':0,'status':'failed','reasons':[reason]}),
                 ('run_end',{'state':'aborted','completed_slots':0,'not_run_slots':[1,2,3],
                    'reasons':[reason]})]
        for kind,data in samples:
            event=self.event(kind,data);self.s.validate_event(event)
            bad=copy.deepcopy(event);bad['data']['unexpected']=None
            with self.subTest(kind=kind),self.assertRaises(self.e): self.s.validate_event(bad)
        timing=samples[3][1]
        for elapsed in [True,1.0,-1,9223372036854775808]:
            bad=dict(timing,elapsed_ns=elapsed)
            with self.assertRaises(self.e): self.s.validate_event(self.event('slot_timing',bad))
        self.s.validate_event(self.event('slot_timing',dict(timing,elapsed_ns=9223372036854775807)))
        self.s.validate_event(self.event('slot_timing',dict(timing,elapsed_ns=None,exit_code=None,
                              termination='launch-failed',elapsed_exceeded_timeout=None)))
        bad=copy.deepcopy(samples[4][1]);bad['streams']['stdout']['path']='captures/000001.stdout'
        with self.assertRaises(self.e): self.s.validate_event(self.event('slot_evidence',bad))
        for bad in [dict(samples[1][1],slot=0),dict(samples[1][1],stage='pre-slot',slot=None),
                    dict(samples[1][1],reasons=[{'code':'made_up'}])]:
            with self.assertRaises(self.e): self.s.validate_event(self.event('fingerprint_check',bad))

    def test_event_sequence_local_invariants(self):
        event=self.event('run_end',{'state':'aborted','completed_slots':0,'not_run_slots':[2,1],
                                  'reasons':[{'code':'internal_error'}]})
        with self.assertRaises(self.e): self.s.validate_event(event)
        event['data']['not_run_slots']=[];event['seq']=1
        with self.assertRaises(self.e): self.s.validate_event(event)
        event['previous_sha256']='0'*64;self.s.validate_event(event)
        event['seq']=1024
        with self.assertRaises(self.e): self.s.validate_event(event)

    def test_seal_allowed_paths_uniqueness_order_and_bounds(self):
        obj={'schema':'benchinterlace.seal.v1','plan_id':'sha256:'+'0'*64,
             'last_event_sha256':'1'*64,'files':[{'path':'plan.json','bytes':1,'sha256':'0'*64}]}
        self.s.validate_seal(obj)
        for path in ['../plan.json','/plan.json','seal.json','events/1.json','captures/000100.stdout','extra']:
            bad=copy.deepcopy(obj);bad['files'][0]['path']=path
            with self.subTest(path=path),self.assertRaises(self.e): self.s.validate_seal(bad)
        bad=copy.deepcopy(obj);bad['files']*=2
        with self.assertRaises(self.e): self.s.validate_seal(bad)
        bad=copy.deepcopy(obj);bad['files'][0]['bytes']=65537
        with self.assertRaises(self.e): self.s.validate_seal(bad)

    def test_report_inventories_codes_rationals_and_suppression(self):
        obj=self.report(); self.s.validate_report(obj)
        for change in [{'warnings':[{'code':'invented','text':'x'}]},
                       {'reasons':[{'code':'invented'}]}, {'analysis_version':''},
                       {'inference_status':'available'}, {'extra':0}]:
            with self.assertRaises(self.e): self.s.validate_report(dict(obj,**change))
        obj.update(plan_id='sha256:'+'0'*64,bundle_sha256='0'*64,
                   evidence_status='complete',inference_status='available',reasons=[],
                   counts={'warmup':dict(planned=0,started=0,timed=0,validated=0,unstarted=0),
                           'measured':dict(planned=4,started=4,timed=4,validated=4,unstarted=0)},
                   descriptive={'n':2,'sum_a_ns':2,'sum_b_ns':4,
                                'mean_a_ns':{'numerator':1,'denominator':1},
                                'mean_b_ns':{'numerator':2,'denominator':1},
                                'mean_difference_ns':{'numerator':1,'denominator':1},
                                'ratio_b_over_a':{'numerator':2,'denominator':1}},
                   test={'method':'exact-paired-assignment-v1','alternative':'two-sided',
                         'statistic_sum_difference_ns':2,'tail_count':2,
                         'assignment_count':4,'p_decimal':'0.500000000000'})
        self.s.validate_report(obj)
        for mutate in [lambda x:x['descriptive']['mean_a_ns'].update(numerator=2,denominator=2),
                       lambda x:x['test'].update(assignment_count=8),
                       lambda x:x['test'].update(p_decimal='0.5'),
                       lambda x:x['test'].update(p_decimal='0.250000000000'),
                       lambda x:x['counts']['measured'].update(unstarted=1),
                       lambda x:x.update(inference_status='withheld'),
                       lambda x:x.update(evidence_status='failed')]:
            bad=copy.deepcopy(obj);mutate(bad)
            with self.subTest(report=bad),self.assertRaises(self.e): self.s.validate_report(bad)

    def test_direct_values_have_bounded_string_and_container_work(self):
        for value in ['x'*4097, {'x'*4097:0}, [0]*100001]:
            with self.subTest(kind=type(value)),self.assertRaises(self.e):
                self.c.canonical_bytes(value)
        self.assertEqual(self.c.parse_json(b'"'+b'x'*4096+b'"',5000),'x'*4096)
        with self.assertRaises(self.e):
            self.c.parse_json(b'"'+b'x'*4097+b'"',5000)

    def test_canonical_api_rejects_boolean_limits_and_nonboolean_flags(self):
        for raw,limit,canonical in [('{}',64,False),(b'{}',True,False),
                (b'{}',0,False),(b'{}',64.0,False),(b'{}',64,1),(b'{}',64,None)]:
            with self.subTest(args=(raw,limit,canonical)),self.assertRaises(self.e):
                self.c.parse_json(raw,limit,canonical)
        with self.assertRaises(self.e): self.c.digest('not bytes')

    def test_control_characters_are_preserved_except_nul(self):
        text='diagnostic\n\x1b[31m\t'
        event=self.event('run_end',{'state':'aborted','completed_slots':0,
            'not_run_slots':[],'reasons':[{'code':'internal_error','detail':text}]})
        self.s.validate_event(event)
        raw=self.c.canonical_bytes(event)
        self.assertNotIn(b'\x1b',raw)
        self.assertEqual(self.c.parse_json(raw,16384,True),event)

    def test_report_version_is_identifiable_before_capability_rejection(self):
        for version in ['0.0.1', 'future-analysis-version']:
            report=self.report();report['analysis_version']=version
            self.s.validate_report(report)
        for version in ['',True,'v'*129]:
            report=self.report();report['analysis_version']=version
            with self.assertRaises(self.e): self.s.validate_report(report)

    def test_recursive_exact_keys_required_fields_and_integer_types(self):
        samples=[(self.spec(),self.s.validate_spec),(self.plan(),self.s.validate_plan),
                 (self.report(),self.s.validate_report)]
        def mutations(value):
            if isinstance(value,dict):
                unknown=copy.deepcopy(value);unknown['UNEXPECTED']=None
                yield unknown
                for key,child in value.items():
                    if key not in ('capture_bytes_per_stream','capture_bytes_total','detail'):
                        missing=copy.deepcopy(value);del missing[key];yield missing
                    for changed in mutations(child):
                        replacement=copy.deepcopy(value);replacement[key]=changed;yield replacement
            elif isinstance(value,list):
                for index,child in enumerate(value):
                    for changed in mutations(child):
                        replacement=copy.deepcopy(value);replacement[index]=changed;yield replacement
            elif type(value) is int:
                yield float(value)
                yield bool(value)
        for sample,validator in samples:
            for changed in mutations(sample):
                if validator is self.s.validate_plan and type(changed) is dict and 'payload' in changed and 'plan_id' in changed:
                    try: self.reseal(changed)
                    except self.e: pass
                with self.subTest(validator=validator.__name__,mutation=changed),self.assertRaises(self.e):
                    validator(changed)

    def test_machine_schemas_exist_and_close_all_object_shapes(self):
        for name in ['spec','plan','event','seal','report']:
            path=Path(__file__).resolve().parents[1]/'schemas'/f'{name}.schema.json'
            self.assertTrue(path.is_file(),str(path))
            doc=json.loads(path.read_text())
            self.assertEqual(doc['$schema'],'https://json-schema.org/draft/2020-12/schema')
            self.assertEqual(doc,self.s.schema_document(name))
            def walk(v):
                if isinstance(v,dict):
                    if v.get('type')=='object': self.assertIs(v.get('additionalProperties'),False)
                    for value in v.values(): walk(value)
                elif isinstance(v,list):
                    for value in v: walk(value)
            walk(doc)

if __name__=='__main__': unittest.main()
