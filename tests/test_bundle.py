import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from tests.fixtures import make_bundle, encode, load_events, write_events, reseal


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=make_bundle(Path(self.tmp.name)/'bundle')
    def tearDown(self): self.tmp.cleanup()
    def read(self):
        from benchinterlace.bundle import read_bundle
        return read_bundle(self.root)
    def test_complete_bounded_reader(self):
        b=self.read(); self.assertFalse(b.problems); self.assertEqual(len(b.events),92); self.assertEqual(len(b.captures),32)
    def test_missing_seal_is_incomplete(self):
        (self.root/'seal.json').unlink(); b=self.read(); self.assertIn('missing_seal',[r['code'] for r in b.reasons]); self.assertFalse(b.malformed)
    def test_capture_mutation_detected(self):
        (self.root/'captures/000000.stdout').write_bytes(b'changed'); self.assertTrue(self.read().malformed)
    def test_symlink_and_fifo_never_opened(self):
        f=self.root/'captures/000000.stdout'; f.unlink(); f.symlink_to('/etc/passwd'); self.assertTrue(self.read().malformed)
        f.unlink(); os.mkfifo(f); self.assertTrue(self.read().malformed)
    def test_unknown_and_oversized_files(self):
        (self.root/'unknown').write_bytes(b'x'); self.assertTrue(self.read().malformed)
        (self.root/'unknown').unlink(); (self.root/'plan.json').write_bytes(b' ' * 65537); self.assertTrue(self.read().malformed)
    def test_chain_and_filename_sequence(self):
        e=self.root/'events/000001.json'; o=json.loads(e.read_bytes()); o['previous_sha256']='0'*64; e.write_bytes(encode(o)); reseal(self.root)
        self.assertTrue(self.read().malformed)
    def test_duplicate_json_key(self):
        f=self.root/'plan.json'; raw=f.read_bytes(); f.write_bytes(raw.replace(b'{',b'{"plan_id":"bad",',1)); self.assertTrue(self.read().malformed)
    def test_seal_missing_entry(self):
        f=self.root/'seal.json'; o=json.loads(f.read_bytes()); o['files'].pop(); f.write_bytes(encode(o)); self.assertTrue(self.read().malformed)
    def test_read_only_bytes_and_mtime(self):
        files=[x for x in self.root.rglob('*') if x.is_file()]; before={str(f):(f.read_bytes(),f.stat().st_mtime_ns) for f in files}
        self.read(); after={str(f):(f.read_bytes(),f.stat().st_mtime_ns) for f in files}; self.assertEqual(before,after)

    def test_root_symlink_rejected_before_content_read(self):
        from benchinterlace.bundle import read_bundle
        from unittest.mock import patch
        link=Path(self.tmp.name)/'link'; link.symlink_to(self.root,target_is_directory=True)
        with patch('benchinterlace.bundle.os.open',side_effect=AssertionError('must not open rejected root')):
            b=read_bundle(link)
        self.assertTrue(b.malformed)
