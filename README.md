# AET-DSS

AET-DSS is an executable reference implementation for collecting **sandboxed, auditable execution trajectories** for dataset preparation. It is deliberately conservative: all file actions are contained below an explicitly supplied sandbox directory, and application, audio, network, process, and memory categories are only registered as no-op sandbox interfaces. It does **not** grant host, network, or production-data access.

## Prerequisites and installation

* Python 3.11 or newer.
* A disposable local directory for each run. Do not point `--sandbox` at a working checkout, home directory, or a directory containing sensitive data.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

The package manifest is `pyproject.toml`; it exposes the `aet-dss` command.

## Runtime and commands

```bash
# initialize a disposable sandbox and ledger
aet-dss seed --sandbox /tmp/aet-dss-demo

# execute the registered file.write tool and emit a JSONL trajectory
aet-dss run --sandbox /tmp/aet-dss-demo --path output.txt --content 'example'

# validate the append-only hash chain
aet-dss audit --sandbox /tmp/aet-dss-demo

# validate trajectory admission (PII/canary/distribution checks)
aet-dss report --sandbox /tmp/aet-dss-demo
```

Output is under `<sandbox>/.aet-dss/`: `ledger.jsonl` is the hash-chained audit log and `trajectories.jsonl` is the training-record JSONL. The example tool output is written inside the sandbox.

## Safety model

TLEG rejects unregistered tools, malformed arguments, paths outside the sandbox, undeclared effects, over-limit changes, and irreversible operations without a pre-action statement. Every allowed invocation records its guard event, pre/post snapshot diff, reversibility metadata, MSCP context manifest (including deterministic compression/eviction), and ledger hash reference. The included trajectory schema labels successful declared-effect state-diff verification as `verification.state_diff_valid`.

Before any fine-tuning use, run `aet-dss audit`, retain its output with the dataset, inspect `ledger.jsonl` in order, and run `aet-dss report`. A report must state `dataset_accepted: true`; it rejects empty batches, PII-like emails/payment-card strings, canary markers, and trajectories without successful diff validation. These checks are safeguards, not a substitute for human privacy/security review.

## Development

```bash
python -m pytest -q
```

Tests use pytest-provided temporary directories only and verify both the hash chain and emitted state-diff validation.
