# AGENTS.md

Instructions for AI coding agents (e.g. OpenAI Codex) working in this
repository.

## Project Purpose

Academic CA-2 case study: *"Third-Party Vendor Access as a Ransomware
Vector: A Cybersecurity Analysis of the ICICI Bank Case."* A synthetic,
local, in-memory simulation comparing an unprotected **Baseline** banking
environment against a Zero-Trust **Protected** environment, to measure how
much defense-in-depth controls reduce ransomware exposure from a compromised
third-party vendor identity. See `README.md` and `docs/METHODOLOGY.md` for
full detail.

## Technology Stack

- Python 3.11+, standard library (`dataclasses`, `unittest`, `csv`, `json`).
- `matplotlib` + `numpy` for chart generation only (`requirements.txt`).
- No web framework, no database, no external services, no network I/O.

## Safety Restrictions (hard constraints — do not relax)

This is a defensive-security academic simulation. Never introduce:

- Real ICICI/banking systems, real customer data, or real credentials.
- Network scanning, external targets, or any outbound network call.
- Credential theft, real privilege-escalation exploits, or persistence
  mechanisms.
- Real malware/ransomware. The "ransomware" module
  (`src/simulation/ransomware_simulator.py`) may only overwrite/rename dummy
  files inside `data/simulation_workspace/` with a harmless text marker — it
  must never touch anything outside the project sandbox.

## Experiment Design

- Same scripted attacker playbook in both scenarios (probe → attempted
  privilege escalation → attempted lateral movement → attempted ransomware
  impact); only the security configuration differs between Baseline and
  Protected. Never make the attacker itself scenario-aware.
- Protected scenario's main experiment assumes the compromised vendor
  identity **already holds an authenticated session**
  (`credential_compromised=True`, `authenticated_session=True`, i.e.
  `SimulationRunner.run_scenario_2_protected(assume_authenticated_session=True)`,
  the default) — this is what makes RBAC/segmentation/detection/containment
  the controls under test, instead of every trial stopping at MFA.
- MFA is tested **separately** via `assume_authenticated_session=False`
  (`tests/test_simulation.py::test_protected_mfa_gate_blocks_credential_only_compromise`).
  Do not make MFA the sole reason the main protected-scenario experiment
  terminates.
- 5 synthetic vendors × 10 trials × 2 scenarios = 100 total trials, fixed
  seed `42` (`src/simulation/engine.py`). Preserve this structure unless
  asked to change it.

## Baseline vs. Protected Architecture

| | Baseline | Protected |
| :--- | :--- | :--- |
| MFA | Not required | Part of the architecture; assumed already satisfied in the main experiment (tested separately) |
| RBAC | All resources permitted | Least privilege — vendor-provisioned resources only |
| Segmentation | Flat / unsegmented | Strict — no cross-zone traffic allowed |
| Detection | Disabled | Active (7 deterministic rules, `src/security/detection.py`) |
| Containment | None | Automated session isolation on CRITICAL/HIGH alert |

## Important Commands

Install:
```bash
pip install -r requirements.txt
```

Run the full simulation (regenerates all results):
```bash
python scripts/run_simulation.py
```

Run tests:
```bash
python -m unittest tests.test_simulation -v
```

## Result Locations

- `results/csv/trial_records.csv` — raw per-trial data (source of truth).
- `results/csv/comparison_metrics.csv` — aggregated metrics.
- `results/summary_report.md` — generated markdown report.
- `results/charts/*.png` — generated figures.
- `logs/*.jsonl` — per-run structured event logs (each rerun overwrites the
  file for the last trial of a given vendor+scenario — this is expected).

## Terminology Requirements

- Call the 100 trials **"50 repeated simulation runs per configuration
  across 5 synthetic vendor profiles"** — never "100 independent real-world
  experiments." The attacker playbook is fixed/deterministic, not adaptive.
- Call the risk score (`src/risk/scoring.py`) a **"project-specific vendor
  risk scoring model"** — never an industry-standard metric (it is not
  CVSS/FAIR/NIST CSF).
- Do not describe MFA as the mechanism that stops the main protected-scenario
  experiment — it is tested as a separate, standalone control.

## Do Not Fabricate Results

- Every metric must be produced by actually running
  `scripts/run_simulation.py` (or the relevant unit test) — never
  hand-written or estimated.
- Before reporting or citing any metric, **open and inspect the raw data
  first**: `results/csv/trial_records.csv`, then confirm
  `results/csv/comparison_metrics.csv` and `results/summary_report.md`
  aggregate it correctly (recompute independently if in doubt — see
  `README.md` for the metric definitions). If numbers don't reconcile, fix
  the code and rerun; do not adjust the report to hide a mismatch.
- Run the test suite and the full simulation after any change to
  `src/simulation/`, `src/security/`, `src/network/`, `src/auth/`, or
  `src/metrics/`, and regenerate `results/` before claiming a change is
  complete.
