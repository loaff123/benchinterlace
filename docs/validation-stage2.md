# Stage 2 validation record (0.1.0a2)

Date: 3 October 2026. Tested runtime: Linux x86_64, CPython 3.12.14.
This is alpha workflow validation with original harmless helpers, not comparative
performance evidence, a platform-matrix claim, or permission to publish.

## Automated checks

- Fresh standard-library full run: 449 tests, 448 passed and one optional SciPy
  check skipped, 56.5 seconds in one observed run
- Separate opt-in exact suite: all 20 passed, including already-installed SciPy
  1.17.0 / NumPy 2.3.5; no dependency installation
- All original statistical/oracle and adversarial tests retained; the two
  Stage 1-only CLI/package scope assertions now reflect plan/run availability
- 34 planner/fingerprint checks; 32 publication/journal checks; 21 lifecycle
  methods; end-to-end workflow and late-failure checks; six interruption methods
  containing 22 boundary cases
- The signal matrix uses real SIGINT/SIGTERM/SIGKILL at three synchronized
  boundaries, tests unrelated-session sentinel survival, and preserves immutable
  evidence prefixes. SIGKILL does not promise runner cleanup: helpers are owned
  and naturally bounded
- Ten finalization injection cases distinguish rejection before final admission,
  admission followed by a link crossing the deadline, and post-commit durability
  tail observations. A rejected seal gate can leave either an unsealed prefix or
  a retained temporary, depending on the exact failure point; neither has inference
- Exact-cap output, global-cap overflow, two-stream floods, arbitrary raw bytes,
  nonzero exit, timeout, readiness-controlled TERM-ignore/KILL, same-group pipe
  holders and silent children are covered
- Controller/thread/observer/pipe-close failure, ECHILD ownership loss, ESRCH,
  EPERM, forbidden group signaling after reap, and exact fake-clock observation
  endpoints are checked without signaling unrelated processes
- Original input/plan mutation, late capture publication failure and failure after
  the last measured timer preserve prior observed timing counts and suppress
  inference; read-only verification leaves bytes/mtime/ctime unchanged
- Fault cuts cover partial writes, ENOSPC, file fsync, hard link, directory fsync,
  temporary unlink, final fsync, mutation and exhaustive seal checks. These unit
  simulations do not prove arbitrary filesystem power-loss durability

## Packaging and resources

Wheel and source distribution were built with already-installed setuptools 84.0.0.
Fresh extracted copies independently passed help, plan, harmless run, analyze and
verify with four validated measured slots. No package was installed. Extracted-
artifact execution is not a substitute for a clean installation matrix.

The same 40-pair resource probe as Stage 1 was repeated with 0.1.0a2, one fresh
parent/worker per case. Mixed signed integers: 2.021328 seconds and 71,664 KiB child
peak RSS; equal extrema: 0.896488 seconds and 62,436 KiB; all zeros: 0.412849 seconds
and 17,536 KiB. Exact numerators remained 74,359,360,546; 2; and 1,099,511,627,776,
respectively, each over 2^40. Workers reported enforced 256 MiB address-space,
30-second CPU and parent-wall bounds. Address-space and RSS are distinct.
These measurements qualify this tested host only.

## Independent review and remaining limits

Independent lifecycle/integration review checked unreaped-leader ownership,
exception cleanup, bounded capture, failure-prefix semantics, cooperative seal
hashing, final admission and metadata privacy. Reproduced findings were fixed
with regressions: controller allocation after spawn; close exceptions losing
observed timing; missing pre-Popen cancellation gate; unresponsive seal hashing;
and misleading input-change reasons for timeout-only fingerprints.

The explicit observed-admission/immutable-commit revision is normative and
explained in [the Linux contract](linux-runner.md). Final seal link/durability
cannot be atomically bounded by time or signal delivery. Hash consistency does not
authenticate assignment, timestamps, unseen attempts or the exact bytes executed.

Still untested: other Python versions/interpreters and macOS/Windows portable
analysis; actual clean installs; network-filesystem durability; complete daemon/
process-group/session-escape containment (not supported); privilege-changing
workloads. Uninterruptible kernel calls, hostile same-user races and runner
SIGKILL remain expressly outside a universal cleanup/security guarantee. Public
release is a separate decision after reviewing these alpha limits.
