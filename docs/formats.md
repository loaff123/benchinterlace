# Frozen formats and semantic replay

The five standalone [JSON Schema documents](../schemas) describe the exact closed inventories. Runtime handwritten validation additionally enforces UTF-8 byte limits, canonical bytes, arithmetic, identities and cross-record rules. No schema supplied by a bundle is loaded or executed.

Canonical bytes are sorted-key, compact-separator JSON with ensure_ascii=True followed by one LF. Plan identity is `sha256:` plus SHA-256 of canonical payload bytes including LF. Event previous_sha256 hashes the entire previous canonical event file. The seal lists every plan, committed event and capture, sorted lexicographically; its own bytes are not listed. Report bundle_sha256 identifies a valid seal. Hashes do not authenticate authorship.

Reject duplicate or unknown keys, floats including exponent-form integers, invalid UTF-8, lone surrogates, NUL, booleans in integer fields, unsupported schema values and excessive bounds. Integer token maximum is 64 decimal digits, depth is 12, strings at most 4096 UTF-8 bytes and JSON nodes at most 100,000 before field-specific limits. Labels are 128 bytes, reasons/warnings 1024 bytes. Free-form controls are escaped for terminal display, never used as instructions.

Limits: plan/spec 64 KiB; 1024 events each <=16 KiB and aggregate <=16 MiB; seal 256 KiB; report JSON/text <=1 MiB; at most 200 captures; per-stream <=1 MiB, global retained capture <=256 MiB; bundle <=288 MiB. Declared-file manifests have <=64 unique files and <=1 GiB total recorded size. Analysis does not open declared files. Spec validators check shape and path text only; planning-time existence/fingerprint checks remain stage 2.

The bundle contains only `plan.json`, `events/000000.json...`, `captures/000000.stdout` and `.stderr`, and `seal.json`. No symlinks, nonregular files, traversal components, absolute bundle entries, unknown files or partial tails are ignored to produce inference. Directory scans and streaming reads are bounded. Descriptor and named-path size/identity/mtime/ctime are checked around reads and again after verification. This reduces accidental races; an actively hostile same-user filesystem is outside the security boundary. An uninterruptible filesystem call is not hard-real-time bounded.

## Exact successful order

1. run_start, pre-run fingerprint
2. For each warmup slot and then measured slot: pre-slot fingerprint, slot_start, slot_timing, slot_evidence, post-slot fingerprint
3. After each second slot: pair_check
4. post-run fingerprint, run_end complete, exhaustive seal

The frozen assignments determine phase/pair/position/arm/slot; readers do not repair or filter observations. Every fingerprint covers all declared files in ID order. Every required output-check claim is recomputed from retained lengths/digests and capture bytes. Failed timing, timeout request, zero duration, nonzero exit, output truncation/incompletion, missing hash/file, cleanup uncertainty and late checks all suppress inference. Once any failure occurs, no new slot may start. A complete run must fit the necessary lower bound of summed nonoverlapping slot durations plus the prescribed 250 ms cleanup grace per slot inside its whole-run budget; this does not authenticate unrecorded I/O or overhead timing. Coherent failure prefixes may finalize as aborted; crashes remain incomplete. Two evidence records require their pair check even on failure.

Counts refer to slots: planned is twice the pair count; started counts plan-matching starts; timed counts durable timing records with nonnull represented elapsed (including failed timings); validated counts slots passing timing, capture, post-slot fingerprint and pair checks; unstarted=planned−started. A failure observed before the final seal-admission checkpoint leaves earlier per-slot facts visible while suppressing all inference. The explicit [observed-admission and immutable-commit exception](linux-runner.md#explicit-finalization-revision-observed-admission-then-immutable-commit) applies to later filesystem, cancellation and CLI-return failures; a complete readable committed bundle is not retroactively revoked. Malformed/foreign identities are not repaired into trusted phase counts. completed_slots in run_end counts slot_evidence records, regardless of their eligibility.

A missing seal, unfinished start or failed final fingerprint is never replaced or repaired. No successful subset receives a full-experiment summary. `verify --report` validates the report and recomputes every deterministic field. This preview verifies its own analysis version only; other versions are explicitly unsupported. Text wording compatibility across versions remains future work.

## Python API

- canonical.canonical_bytes / parse_json / digest
- schema.validate_spec / validate_plan / validate_event / validate_seal / validate_report
- exact.exact_counts(differences, alternative) → (unreduced_tail_count, 2**n)
- analysis_worker.run_exact(differences, alternative) → available/unsupported record
- report.analyze(bundle_path) → validated report dictionary
- report.verify(bundle_path, report_path=None) → replayed dictionary, or ValidationError for a mismatched/unsupported report
- report.render_text(report) → escaped text

The low-level pure exact kernel does not establish collection eligibility. Only analysis of a complete validated bundle exposes an inference-bearing report.
