"""Build and clean-install both distribution paths, with no package-index access.

Run from the source root with an already installed setuptools>=77 and wheel.
Distribution archives and harmless command executions live in a temporary folder.
This Linux release check does not measure or claim a performance improvement.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile


def checked(argv, cwd, env):
    subprocess.run(list(map(str, argv)), cwd=cwd, env=env, check=True, timeout=120)


def smoke(wheel, root, destination, env):
    venv.EnvBuilder(with_pip=True).create(destination / "venv")
    python = destination / "venv/bin/python"
    console = destination / "venv/bin/benchinterlace"
    outside = destination / "outside"
    outside.mkdir()
    checked([python, "-m", "pip", "install", "--no-deps", "--no-index", wheel], outside, env)
    checked([python, "-I", "-c", "import benchinterlace; assert 'site-packages' in benchinterlace.__file__"], outside, env)
    checked([python, "-m", "benchinterlace", "--help"], outside, env)
    checked([console, "--help"], outside, env)
    helper = outside / "harmless.py"
    helper.write_text("print('owned packaging smoke')\n", encoding="utf-8")
    spec = dict(
        schema="benchinterlace.spec.v1", workload="Owned harmless package smoke",
        cwd=str(outside), commands={a: {"argv": [str(python), str(helper)]} for a in ("A", "B")},
        files=[{"id": "helper", "path": str(helper)}], measured_pairs=2, warmup_pairs=0,
        alternative="two-sided", command_timeout_ns=2_000_000_000,
        run_timeout_ns=15_000_000_000, output_check={"mode": "equal-within-pair"},
    )
    (outside / "experiment.json").write_text(json.dumps(spec), encoding="utf-8")
    for args in (
        ["plan", "--spec", "experiment.json", "--out", "plan.json"],
        ["run", "--plan", "plan.json", "--out", "comparison"],
        ["analyze", "comparison", "--out", "report"],
        ["verify", "comparison", "--report", "report/report.json"],
    ):
        checked([console, *args], outside, env)
    report = json.loads((outside / "report/report.json").read_text())
    assert report["evidence_status"] == "complete"
    assert report["counts"]["measured"]["validated"] == 4
    shutil.copytree(root / "examples/teaching/bundle", outside / "teaching")
    checked([console, "analyze", "teaching", "--out", "teaching-report"], outside, env)
    checked([console, "verify", "teaching", "--report", "teaching-report/report.json"], outside, env)
    assert (outside / "teaching-report/report.json").read_bytes() == (root / "examples/teaching/report.json").read_bytes()


def main():
    assert sys.platform == "linux", "Complete-workflow package qualification is Linux-only"
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONHOME"):
        env.pop(key, None)
    env["PIP_NO_INDEX"] = "1"
    with tempfile.TemporaryDirectory(prefix="benchinterlace-package-") as temporary:
        tmp = Path(temporary)
        dist = tmp / "dist"
        dist.mkdir()
        # Each backend call may mutate sys.argv; keep the invocations separate.
        for builder in ("build_sdist", "build_wheel"):
            code = f"from setuptools.build_meta import {builder}; import sys; {builder}(sys.argv[1])"
            checked([sys.executable, "-c", code, dist], root, env)
        [sdist] = dist.glob("*.tar.gz")
        [wheel] = dist.glob("*.whl")
        extracted = tmp / "extracted"
        extracted.mkdir()
        with tarfile.open(sdist) as archive:
            for member in archive.getmembers():
                assert member.isfile() or member.isdir()
                assert not member.name.startswith("/") and ".." not in Path(member.name).parts
            archive.extractall(extracted, filter="data")
        [source] = extracted.iterdir()
        rebuilt = tmp / "rebuilt"
        rebuilt.mkdir()
        checked([sys.executable, "-c", "from setuptools.build_meta import build_wheel; import sys; build_wheel(sys.argv[1])", rebuilt], source, env)
        [rebuilt_wheel] = rebuilt.glob("*.whl")
        with zipfile.ZipFile(wheel) as first, zipfile.ZipFile(rebuilt_wheel) as second:
            assert set(first.namelist()) == set(second.namelist())
            for name in first.namelist():
                assert first.read(name) == second.read(name), name
        for label, artifact in (("direct", wheel), ("sdist-rebuilt", rebuilt_wheel)):
            destination = tmp / label
            destination.mkdir()
            smoke(artifact, root, destination, env)
            print(f"PASS: {label} wheel, offline clean install, outside-checkout complete workflow", flush=True)


if __name__ == "__main__":
    main()
