"""Measure original n=40 kernel stress fixtures; no benchmark command is run."""

import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from benchinterlace.analysis_worker import run_exact


def measure(case):
    if case == "mixed":
        values, state = [], 0x42494E5445524C41
        for i in range(40):
            state = (6364136223846793005 * state + 1442695040888963407) & ((1 << 64) - 1)
            value = (state >> 1) or 1
            values.append(value if i % 3 else -value)
        expected = 74359360546
    elif case == "extrema":
        values, expected = [(1 << 63) - 2] * 40, 2
    elif case == "powers":
        values, expected = [1 << i for i in range(40)], 2
    elif case == "balanced":
        values, expected = [(1 << 63) - 2, -((1 << 63) - 2)] * 20, 1 << 40
    else:
        assert case == "zeros"
        values, expected = [0] * 40, 1 << 40
    start = time.monotonic()
    result = run_exact(values, "two-sided")
    elapsed = time.monotonic() - start
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    assert result["status"] == "available", result
    assert (result["tail_count"], result["assignment_count"]) == (expected, 1 << 40)
    assert result["limits"]["memory_enforcement"] == "address-space"
    assert result["limits"]["address_space_bytes"] <= 256 * 1024 * 1024
    assert result["limits"]["cpu_seconds"] <= 30
    print(json.dumps(dict(case=case, elapsed_seconds=elapsed, child_peak_rss_kib_linux=usage.ru_maxrss,
        interpreter=sys.version, platform=platform.platform(), cpu_count=os.cpu_count(), result=result)), flush=True)


if __name__ == "__main__":
    assert sys.platform == "linux", "These resource measurements are Linux-only"
    if len(sys.argv) == 2:
        measure(sys.argv[1])
    else:
        for case in ("mixed", "extrema", "zeros", "powers", "balanced"):
            subprocess.run([sys.executable, __file__, case], check=True, timeout=45)
