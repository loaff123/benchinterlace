# Stage 1 validation record

This is the preserved historical Stage 1 offline-analysis record. See [Stage 2 validation](validation-stage2.md) for the later collection workflow.

Final integration run on 3 October 2026: CPython 3.12.14/Linux x86_64, `BENCHINTERLACE_SCIPY_CROSSCHECK=1 python -m unittest discover -v`: **344 tests passed in 12.334 seconds**, including the optional installed-reference check. Without that opt-in, 343 pass and one optional test skips. Timing is a single observed run and is not a test-suite performance promise.

Coverage and independent evidence:

- An independent author wrote the brute-force oracle without reading production kernel code
- Exhaustive vectors over {−2,−1,0,1,2}, n=2…6: 19,525 vectors, 39,050 exact-tail comparisons, 2,222,200 enumerated assignments
- Deterministic generated cases through n=12: 132 vectors, 264 comparisons, 196,512 assignments
- Optional already-installed SciPy 1.17.0/NumPy 2.3.5: six fixtures, twelve tail comparisons plus full reference multiset agreement
- Hand-counted eight-pair 2/256 fixture; T=0 one-sided 3/4; ties/zeros; 2^80 cancellation; scaling/permutation/arm-swap identities
- Fixed-slot trend and all-attainable-threshold assignment error bounds; explicit conditional-eligibility selection counterexample
- 248 independent adversarial integration tests, including all 37 events removed individually both raw and rehashed/resealed, all 12 captures in the smaller fixture, all six final crash boundaries and eight unavailable-stream failure positions
- All report leaf fields tampered individually; current-version semantic replay, null suppression and explicit unsupported-version behavior
- All five JSON Schema documents passed Draft 2020-12 schema checks and matched runtime inventory generation
- Compileall passed; all three checked-in complete/failed/interrupted example reports replayed exactly
- Wheel and sdist built using existing setuptools; isolated extracted-artifact help/analyze/verify round trips passed. No dependency/package installation was performed

Fresh independent whole-code/statistical review also exercised 218 resealed sequence/identity mutations and a twelve-case late/unavailable matrix. Findings were reproduced with failing regression tests before repairs: whole-run lower-bound consistency (including prescribed cleanup grace), malformed cross-phase timing-count corruption, foreign-plan count trust, content reads through a rejected root symlink, and incorrect invented interruption reasons.

See [resource measurements](resources.md) for maximum-pair evidence and [remaining contract](stage2-contract.md) for current runner, publication and release-matrix status. Only this Linux/CPython interpreter was measured/tested. No command timing is presented as collected evidence, and no external recorded command was executed by the analyzer or tests.

The final integration run includes one additional test-first text-rendering fix after the independent review: reason records without prose no longer add trailing whitespace. This changes only text formatting; frozen JSON reports and statistical results are unchanged.
