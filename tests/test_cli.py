import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tests.fixtures import make_bundle


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.base=Path(self.tmp.name); self.root=make_bundle(self.base/'bundle')
    def tearDown(self): self.tmp.cleanup()
    def cli(self,*args): return subprocess.run([sys.executable,'-m','benchinterlace',*map(str,args)],capture_output=True,text=True,timeout=15)
    def test_help_exposes_complete_workflow(self):
        p=self.cli('--help'); self.assertEqual(p.returncode,0,p.stderr); self.assertIn('analyze',p.stdout); self.assertIn('verify',p.stdout); self.assertIn('{plan,run,analyze,verify}',p.stdout)
    def test_round_trip_create_only(self):
        out=self.base/'reports'; p=self.cli('analyze',self.root,'--out',out); self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual({f.name for f in out.iterdir()},{'report.json','report.txt'})
        self.assertEqual(self.cli('verify',self.root,'--report',out/'report.json').returncode,0)
        self.assertEqual(self.cli('analyze',self.root,'--out',out).returncode,2)
    def test_nested_output_refused_without_mutation(self):
        p=self.cli('analyze',self.root,'--out',self.root/'nested'); self.assertEqual(p.returncode,2); self.assertFalse((self.root/'nested').exists())
    def test_invalid_evidence_still_has_diagnostic_report(self):
        (self.root/'seal.json').unlink(); out=self.base/'reports'; p=self.cli('analyze',self.root,'--out',out); self.assertEqual(p.returncode,3,p.stderr); self.assertTrue((out/'report.json').exists())
    def test_unknown_command_refused(self): self.assertEqual(self.cli('run',self.root).returncode,2)

    def test_report_permissions_are_owner_private(self):
        out=self.base/'private-report'
        old=os.umask(0)
        try: result=self.cli('analyze',self.root,'--out',out)
        finally: os.umask(old)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(out.stat().st_mode & 0o777,0o700)
        for path in out.iterdir(): self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_offline_import_graph_does_not_load_runner(self):
        code="import sys; from benchinterlace.report import verify; verify(sys.argv[1]); assert 'benchinterlace.runner_linux' not in sys.modules"
        result=subprocess.run([sys.executable,'-c',code,str(self.root)],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)
