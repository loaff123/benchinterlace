# BenchInterlace

Stage 2 alpha: a bounded offline plan → run → analyze → verify workflow for comparing two trusted foreground commands on one workload.

Production plan creation and one-shot Linux collection now accompany the Stage 1 exact-analysis core. This is still an alpha: Linux/CPython 3.12 and 3.13 were independently tested before publication; hosted CI checks Python 3.11–3.13, and macOS/Windows qualification remains open, and nothing here establishes authentic provenance or a performance win. The included teaching examples are original synthetic data, not measurements.

## Get started on Linux

Python 3.11 or newer is required. Clone this repository for the code, schemas, tests and synthetic examples:

```sh
git clone https://github.com/loaff123/benchinterlace.git
cd benchinterlace
python -m benchinterlace --help
```

Source-tree use needs no installation or network access. To install the console command in a virtual environment:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install .
benchinterlace --help
```

The build requires setuptools 77 or newer; pip may download build tooling. Runtime dependencies are standard-library only. This GitHub publication does not make a PyPI package available. The wheel contains the CLI/library; obtain the synthetic examples and schemas from this repository or the source distribution.

## Run your own trusted commands

Create a JSON specification with absolute executable paths and explicit argument arrays. See [the specification fields](docs/formats.md) and [JSON Schema](schemas/spec.schema.json) and the illustrative `examples/experiment.template.json`. Replace its paths with your own trusted already-built programs and declared input files, then run:

```sh
python -m benchinterlace plan --spec experiment.json --out plan.json
# Inspect plan.json before executing either command
python -m benchinterlace run --plan plan.json --out comparison-001
python -m benchinterlace analyze comparison-001 --out comparison-001-report
python -m benchinterlace verify comparison-001 --report comparison-001-report/report.json
```

Every output target must be new. Do not put secrets in argv, paths, labels or output. There is no shell expansion or PATH search. Name an interpreter explicitly and declare its script; direct shebang execution is refused. Commands must remain foreground and wait for their work. They can have arbitrary side effects: this is not a sandbox. No user command is executed by analyze or verify.

Read the [Linux lifecycle and observed final-commit boundary](docs/linux-runner.md) before relying on timeouts or cleanup. Timeout checks do not make spawn or filesystem calls hard-real-time. A readable complete sealed artifact can exist after a final durability-tail/CLI error; commitment is the admitted create-only seal link, not successful CLI return.

## Try the frozen teaching example

Python 3.11 or newer; no third-party runtime dependencies:

```sh
python -m benchinterlace --help
python -m benchinterlace analyze examples/teaching/bundle --out /tmp/benchinterlace-example-report
python -m benchinterlace verify examples/teaching/bundle --report /tmp/benchinterlace-example-report/report.json
```

The output directory must be new and outside the bundle. Verification writes nothing and never opens the executable/input paths recorded inside the plan. It runs only the product's own isolated analysis worker. Source-tree use needs no installation. A standard Python wheel can also be built with an already-available setuptools backend.

The synthetic example has eight pairs, mean A=170 ms, mean B=180 ms, observed mean(B)/mean(A)=18/17, mean difference=10 ms, and an inclusive exact two-sided tail of 2/256=0.007812500000. Deleting any required evidence suppresses inference. It never analyzes a selected complete subset or silently replaces a failed pair.

## What the alpha does

- Strict versioned spec/plan/event/seal/report schemas and bounded handwritten validators
- Canonical JSON, exact SHA-256 byte consistency, exhaustive seals and chained events
- Read-only bounded regular-file reads, symlink refusal and mutation detection
- Ordered semantic replay of every warmup and measured slot and every required check
- Exact integer meet-in-the-middle counting, inclusive ties, retained zero multiplicities
- Exact reduced descriptive ratios and deterministic JSON/text reports
- Full report recomputation, including identities, counts, warnings, null suppression and exact fractions

A failed or incomplete attempt has no p-value or full-experiment effect summary. A complete bundle that cannot fit supported analysis limits also has no inference; no approximation is substituted. Exit codes: 0 available conditional calculation, 2 CLI/output target error, 3 invalid/incomplete/failed evidence or report mismatch, 4 unsupported resource/capability, 5 operational I/O, 130 SIGINT, 143 SIGTERM. Code 0 does not mean a performance win, equivalence or no regression. Known alpha diagnostic limitation: unsupported filesystem operations can currently surface as operational exit 5 instead of capability exit 4; they still fail closed and preserve available evidence.

## Assumptions matter

These are assumption-qualified calculations. The global sharp null says every scheduled measured slot's elapsed duration is unchanged under every complete AB/BA assignment history, including direct and carryover effects. Assignment must genuinely use independent fair order bits. Pairing alone does not establish either condition.

Observed mean(B)/mean(A) is descriptive only. There are no automatic regression gates, confidence intervals, effect-size thresholds, causal-mechanism claims or equivalence findings. A nonsignificant p-value is not evidence of equivalence.

Hashes show consistency, not truthful timing, genuine randomness, authentic provenance or independent preregistration. Repeating until success or a favorable result, choosing plans after previews, suppressing attempts, or conditioning on assignment-dependent completion can invalidate the simple interpretation. The tool cannot see unreported attempts and applies no multiplicity adjustment.

See [statistical contract](docs/statistics.md), [format/replay contract](docs/formats.md), [resource evidence](docs/resources.md), and [runner/release status](docs/stage2-contract.md).

## Scope and resource limits

2–40 measured pairs, 0–10 warmup pairs; at most 100 slots. Raw durations are integers in 0…2^63−1; inference requires positive durations strictly below the frozen command timeout and all evidence complete. An exact worker uses a 128 MiB conservative structural allocation budget, a 30-second wall watchdog, and where available a 30-second CPU/256 MiB address-space ceiling. Address-space is not RSS. Platforms lacking OS memory enforcement disclose structural-only limits.

The maximum was independently measured on CPython 3.12.14 and 3.13.5/Linux x86_64. The code targets Python 3.11+. The [hosted CI workflow](.github/workflows/ci.yml) checks full Linux tests, five maximum-pair resource cases, offline wheel/sdist installation, and harmless outside-checkout workflows. Consult the exact commit’s CI result before treating that matrix row as passed. macOS/Windows analysis support remains unqualified; collection is Linux-only. Non-CPython allocation models are unsupported. These bounds protect the analyzer; there is no benchmark-program sandbox for the trusted commands you choose to run.

## Development checks

```sh
python -m unittest discover -v
BENCHINTERLACE_SCIPY_CROSSCHECK=1 python -m unittest tests.test_exact -v
```

The standard-library suite is sufficient. The optional reference uses SciPy/NumPy only if already installed; they are not dependencies. It is not authoritative for integer ties. The decisive independently authored oracle enumerates all sign assignments for all 19,525 vectors over {−2,−1,0,1,2} at n=2…6, plus generated cases through n=12. Original fixtures and code are MIT-licensed. Do not execute recorded commands from any evidence bundle.

CI uses read-only repository permissions and pinned official GitHub Actions. The optional SciPy reference job is separate from the dependency-free suite; packaging tests cover current setuptools and the 77.0.3 minimum series. Neither CI success nor an exact p-value is an automatic performance-regression gate.
