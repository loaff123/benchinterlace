# Linux foreground collection contract

This alpha implements a dedicated `run` CLI on tested Linux/CPython. It runs only
explicit absolute argv arrays chosen by the user. There is no shell parsing,
PATH lookup, command download, network client, setup hook, external checker,
resume, retry, hardware tuning or program sandbox. A selected program can still
read/write files, allocate resources, access a network and have other side effects.
Run only programs you trust; use offline workloads when offline execution matters.

## Planning and execution

Planning resolves initial executable/file aliases once, rejects direct shebang
execution, fingerprints bounded regular files and independently draws an OS-backed
bit per warmup/measured pair. There is no seed, balancing or redraw option. Name an
interpreter explicitly and declare its script. Runtime dependencies are not
inferred. Fingerprints do not prove the exact bytes eventually executed through a
pathname: parent replacement, restored-between-check changes, undeclared inputs,
libraries and an actively hostile same-user filesystem remain outside the boundary.

The plan, output path and capture files are create-only. Directories are private
0700 and new files 0600. Inputs and both plan copies are checked before collection,
before/after each slot and at finalization. The inherited environment is copied once
in memory and never serialized, hashed or displayed. Metadata records interpreter,
architecture and timer properties, not hostname, username or environment values.
Never put secrets in argv, paths, labels or command output; the evidence retains
those declared strings and bounded raw output.

## Time and process ownership

Timing starts immediately before explicit `Popen(..., shell=False,
start_new_session=True)` and ends when the WNOWAIT observer publishes leader exit
under the same lock used for timeout decisions. It includes launch, scheduling,
GIL/mutex delay and concurrent bounded capture overhead. It excludes later hash,
comparison, fingerprint, cleanup and publication work. No process-overhead
subtraction or sub-millisecond accuracy is promised.

The leader remains unreaped while its fresh process group receives TERM, a full
250 ms cleanup grace, and KILL. Before each signal a nonblocking WNOWAIT ownership
probe detects unexpected reaping; ownership loss prevents further group signals.
No Popen reaping/signal helper is used during this phase. The sole owner reaps only
after signaling ends. A normal exit first allows up to 250 ms for pipe EOF. A pipe
holder is reported incomplete; EOF is not proof that no descendants remain. Silent
same-group descendants can be killed without detection.

Commands must wait for their work and remain foreground: no daemonization, session
or process-group escape, changed credentials or detached work. This is not escaped
descendant containment. No unrelated process scan or broad signal is used. A child
still unobservable one second after final KILL gives cleanup-unconfirmed and no next
slot. Uninterruptible sleep, a stuck spawn/filesystem call, SIGKILL to the runner,
power loss and escaping descendants prevent universal hard cleanup guarantees.

Stdout/stderr are drained concurrently, at most one 64-KiB read per ready stream
per turn. Retained prefixes honor both per-stream and global caps. A cap breach
requires an actually observed extra byte; reaching the cap exactly is not a breach.
No stream decoding or disk writes occur during the measured interval. Timing is
published before fallible capture hashing/publication. Every failed/attempted fact
is retained; failure stops the next slot and suppresses inference over the whole
attempt, including successful earlier timings.

## Explicit finalization revision: observed admission, then immutable commit

The initial design said that the whole-run deadline included all finalization.
That is not achievable as a hard completion guarantee with blocking filesystem
calls and an immutable create-only seal. This alpha uses the following explicit
revision; it does not claim that a preflight check bounds a later filesystem call.

The clock begins before exclusive output creation. Collection, cleanup, checks,
journal work and seal preparation consume the observed run budget. No new slot is
admitted after an observed deadline/cancellation. Failed attempts may finish bounded
best-effort cleanup/evidence after the budget. A complete attempt's `run_end` is
published before preparing its seal.

After exhaustive inventory verification, seal-temporary write/fsync/close and
final mutation checks, the runner makes its last deadline/cancellation admission
check immediately before the create-only seal link. A rejected gate leaves an
unsealed prefix; it never rewrites the already-published terminal event. A
successful admitted link is the logical evidence commit. The check cannot be
atomic with time or signal delivery: the admitted link itself can block across a
deadline, or cancellation can arrive immediately after the check. Those later
observations do not revoke the committed evidence.

Directory fsync, temporary unlink and final directory fsync follow the link.
They, signal delivery and CLI return may fail after commitment. Such errors are
reported operationally and never trigger an overwrite, post-seal invalidation
marker or an automatic retry. A temporary left behind makes the bundle
nonexhaustive/ineligible. If the readable bundle is complete and internally
consistent, offline verification may accept it even when the collection CLI did
not return success. A valid readable seal is not proof of a successful CLI return,
a particular wall-clock commit time, authentic randomization, or unconditional
power-loss durability. Unit fault injection cannot prove arbitrary filesystem
crash behavior; network filesystems are outside the tested durability contract.

Known alpha diagnostic limitation: unsupported filesystem primitives (for example
EOPNOTSUPP from hard-link creation or EINVAL from directory fsync) can currently
return operational exit 5 rather than capability exit 4. The operation remains
unsuccessful and preserves available evidence. Pre-commit failures leave no eligible
seal; the documented post-commit exception still applies to a complete readable
artifact. No failed measurement is promoted to eligible evidence.
These errno examples do not justify treating every similarly coded error as an
unsupported capability.

## Evidence outcomes

A failed but finalized run has an aborted terminal event and exhaustive seal when
possible. A crash or publication failure keeps its durable prefix and any temporary
tail. A start without timing/evidence means execution outcome unknown, even if the
crash happened before launch. Verification is read-only: it does not remove tails,
repair, resume, rerun commands or clean up processes. Two slot-evidence records
require the authoritative pair check, even if one failed. No successful subset is
substituted for the frozen experiment.
