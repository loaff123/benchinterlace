import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tests.fixtures import make_bundle, encode


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=make_bundle(Path(self.tmp.name)/'bundle')
    def tearDown(self): self.tmp.cleanup()
    def analyze(self):
        from benchinterlace.report import analyze
        return analyze(self.root)
    def test_teaching_exact_descriptive_and_test(self):
        r=self.analyze(); self.assertEqual(r['evidence_status'],'complete'); self.assertEqual(r['inference_status'],'available')
        self.assertEqual(r['descriptive']['mean_a_ns'],{'numerator':170000000,'denominator':1})
        self.assertEqual(r['descriptive']['mean_b_ns'],{'numerator':180000000,'denominator':1})
        self.assertEqual(r['descriptive']['mean_difference_ns'],{'numerator':10000000,'denominator':1})
        self.assertEqual(r['descriptive']['ratio_b_over_a'],{'numerator':18,'denominator':17})
        self.assertEqual(r['test']['tail_count'],2); self.assertEqual(r['test']['assignment_count'],256); self.assertEqual(r['test']['p_decimal'],'0.007812500000')
    def test_missing_seal_suppresses_all_summary(self):
        (self.root/'seal.json').unlink(); r=self.analyze(); self.assertEqual(r['inference_status'],'withheld'); self.assertIsNone(r['test']); self.assertIsNone(r['descriptive']); self.assertEqual(r['counts']['measured']['timed'],16)
    def test_unsupported_worker_suppresses_all_summary(self):
        from benchinterlace import report
        with patch.object(report,'run_exact',return_value={'status':'unsupported','reason':{'code':'resource_limit','detail':'test limit'},'limits':{'memory_enforcement':'address-space'}}):
            r=self.analyze()
        self.assertEqual(r['evidence_status'],'complete'); self.assertEqual(r['inference_status'],'unsupported'); self.assertIsNone(r['descriptive']); self.assertIsNone(r['test'])
    def test_all_report_fields_semantically_replayed(self):
        from benchinterlace.report import verify
        from benchinterlace.errors import ValidationError
        r=self.analyze(); path=Path(self.tmp.name)/'report.json'; path.write_bytes(encode(r)); self.assertEqual(verify(self.root,path),r)
        def leaves(value,path=()):
            if isinstance(value,dict):
                for k,v in value.items(): yield from leaves(v,path+(k,))
            elif isinstance(value,list):
                for k,v in enumerate(value): yield from leaves(v,path+(k,))
            else: yield path,value
        checked=0
        for address,value in leaves(r):
            tampered=copy.deepcopy(r); at=tampered
            for part in address[:-1]: at=at[part]
            at[address[-1]]=value+1 if type(value) is int else ('tampered' if value is None else str(value)+'tampered')
            path.write_bytes(encode(tampered))
            with self.subTest(address=address):
                with self.assertRaises(ValidationError): verify(self.root,path)
            checked+=1
        self.assertGreater(checked,30)
    def test_failed_report_cannot_reintroduce_p_value(self):
        from benchinterlace.report import verify
        from benchinterlace.errors import ValidationError
        r=self.analyze(); (self.root/'seal.json').unlink(); path=Path(self.tmp.name)/'report.json'; path.write_bytes(encode(r))
        with self.assertRaises(ValidationError): verify(self.root,path)
    def test_warnings_are_visible_and_no_gate(self):
        from benchinterlace.report import render_text
        r=self.analyze(); codes={w['code'] for w in r['warnings']}
        self.assertTrue({'assumptions_unverified','repeated_attempts_uncontrolled','selection_not_adjusted','no_complete_provenance'}.issubset(codes))
        text=render_text(r); self.assertIn('2/256',text); self.assertIn('18/17',text); self.assertIn('two-sided',text); self.assertNotIn('PASS',text)
    def test_render_escapes_terminal_controls(self):
        from benchinterlace.report import render_text
        r=self.analyze(); r['reasons']=[{'code':'invalid_schema','detail':'evil\x1b[31m\ntext'}]
        text=render_text(r); self.assertNotIn('\x1b',text); self.assertIn('\\u001b',text)

    def test_reason_without_detail_has_no_trailing_whitespace(self):
        from benchinterlace.report import render_text
        r=self.analyze(); r['reasons']=[{'code':'input_changed'}]
        self.assertTrue(all(line==line.rstrip() for line in render_text(r).splitlines()))
