# Measured resource evidence

These are analysis-worker measurements on one host, not command-performance results or a portable release claim.

Environment: CPython 3.12.14, Clang 22.1.3, Linux 6.18.44 x86_64, 9 logical CPUs reported. Date: 3 October 2026. `/usr/bin/time` was unavailable. Separate Python invocations measured monotonic elapsed, child CPU and `resource.getrusage(RUSAGE_CHILDREN).ru_maxrss`; Linux reports the latter in KiB. Address-space and RSS are distinct.

All cases have 40 differences, denominator 1,099,511,627,776, enforced 256 MiB address-space and 30 CPU seconds in the child, and a 30-second parent wall watchdog.

- Deterministic mixed signed 63-bit LCG values: two-sided numerator 74,359,360,546; elapsed 1.918879 s; child CPU 1.918389 s; child peak RSS 71,652 KiB; structural estimate 72,357,600 bytes
- Forty equal differences of (2^63−2): two-sided numerator 2; elapsed 0.871802 s; CPU 0.871334 s; peak RSS 62,420 KiB
- Forty zeros, B-slower: numerator 1,099,511,627,776; elapsed 0.434510 s; CPU 0.433949 s; peak RSS 17,536 KiB

Maximum 40 passed these measured gates; it was not reduced. This section records the original CPython 3.12 measurements; later independent CPython 3.13 checks are summarized in the README. macOS/Windows remain unqualified. CPython object-size accounting estimates right-side integer objects, pointer/list allocation overlap, sorting scratch, input/slice pointers, temporary integers and extra allocator overhead before allocation. It rejects estimates above 128 MiB. Left sums are streamed. Non-CPython allocation models are rejected pending separate review/measurement.

On systems without address-space enforcement, reports explicitly say structural allocation cap only. Worker death, memory failure, failure to apply or verify an available OS limit, or watchdog expiry returns unsupported with null inference. There is no approximation or silent continuation beyond declared time limits. A fresh host that cannot admit the bounded worker may receive unsupported even at a previously measured pair count.

## Reproduce the measurements

Run this POSIX/Linux probe from the source root. Each shell iteration creates a fresh measurement parent with exactly one product-owned worker; this keeps child peak RSS independent across cases. Stress-test differences are pure-kernel inputs and can exceed the smaller duration bounds eligible under an experiment's command timeout. No benchmark program is executed.

```sh
for case in mixed extrema zeros; do
  python - "$case" <<'PY'
import json, os, platform, resource, sys, time
from benchinterlace.analysis_worker import run_exact
case = sys.argv[1]
if case == 'mixed':
    values = []
    state = 0x42494E5445524C41
    for i in range(40):
        state = (6364136223846793005 * state + 1442695040888963407) & ((1 << 64) - 1)
        value = (state >> 1) or 1
        values.append(value if i % 3 else -value)
    alternative, expected = 'two-sided', 74359360546
elif case == 'extrema':
    values, alternative, expected = [(1 << 63) - 2] * 40, 'two-sided', 2
else:
    values, alternative, expected = [0] * 40, 'B-slower', 1 << 40
start = time.monotonic()
result = run_exact(values, alternative)
elapsed = time.monotonic() - start
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
assert result['status'] == 'available'
assert result['tail_count'] == expected
assert result['assignment_count'] == 1 << 40
print(json.dumps(dict(fixture=case, vector=values, alternative=alternative,
    system=platform.system(), kernel=platform.release(), machine=platform.machine(),
    logical_cpu_count=os.cpu_count(), interpreter=sys.version, elapsed_seconds=elapsed,
    child_cpu_seconds=usage.ru_utime+usage.ru_stime,
    child_peak_rss_kib_linux=usage.ru_maxrss, result=result), sort_keys=True))
PY
done
```
