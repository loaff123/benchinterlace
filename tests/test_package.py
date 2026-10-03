from pathlib import Path
import tomllib
import unittest


class PackageTests(unittest.TestCase):
    def test_metadata_and_public_scope(self):
        root=Path(__file__).resolve().parents[1]
        self.assertTrue((root/'pyproject.toml').is_file())
        config=tomllib.loads((root/'pyproject.toml').read_text())
        self.assertEqual(config['project']['requires-python'],'>=3.11')
        self.assertEqual(config['project']['dependencies'],[])
        self.assertEqual(config['project']['scripts']['benchinterlace'],'benchinterlace.cli:main')
        self.assertIn('MIT License',(root/'LICENSE').read_text())
        self.assertIn('Stage 1',(root/'README.md').read_text())
        self.assertTrue((root/'benchinterlace/runner_linux.py').exists())

    def test_build_backend_floor_supports_spdx_license_metadata(self):
        root=Path(__file__).resolve().parents[1]
        config=tomllib.loads((root/'pyproject.toml').read_text())
        self.assertEqual(config['project']['license'],'MIT')
        self.assertEqual(config['build-system']['build-backend'],'setuptools.build_meta')
        self.assertEqual(config['build-system']['requires'],['setuptools>=77'])
