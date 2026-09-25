# Third-Party Vendor Access as a Ransomware Vector

**A Cybersecurity Analysis of the ICICI Bank Case (CA-2 Academic Case Study, 2025–26)**

A fully synthetic, local, in-memory simulation of how compromised third-party
vendor access can become a ransomware vector in a banking environment, and
how Zero-Trust controls (RBAC, network segmentation, MFA, detection,
automated containment) prevent or contain that impact.

> **Safety:** No real ICICI or banking systems, no real credentials, no
> network scanning, no credential theft, no real malware/ransomware, and no
> privilege-escalation exploits are implemented anywhere in this repository.
> Everything — vendors, banking assets, transactions, and the "ransomware"
> impact — is synthetic and confined to this project's sandbox. See
> [Safety & Limitations](#safety-limitations) below and
> [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) Section "Academic Integrity &
> Safety Statement".

## 1. Project Purpose

This project supports the CA-2 university cybersecurity case study *"Third-Party
Vendor Access as a Ransomware Vector: A Cybersecurity Analysis of the ICICI
Bank Case."* It builds a synthetic banking environment with synthetic
third-party vendors, then runs two comparative experiments — an unprotected
**Baseline** and a Zero-Trust **Protected** environment — to measure, with
real generated data (not hand-authored numbers), how much a defense-in-depth
architecture reduces ransomware exposure from a compromised vendor identity.

## 2. Research Question

> How can compromised third-party vendor access become a potential ransomware
> attack vector in a banking environment, and what security controls can
> prevent or contain its impact?

Critically, this project asks what happens **after** a vendor identity is
compromised and already operating inside an authenticated session — not how
that access was originally obtained, and not merely whether MFA can be
defeated. See [Baseline vs. Protected](#4-baseline-environment) below.

## 3. Experimental Design

- **Synthetic banking environment:** 10 assets across 4 trust zones
  (`VENDOR_ZONE`, `INTERNAL_ZONE`, `SENSITIVE_ZONE`, `BACKUP_ZONE`) — see
  `src/models/resource.py`.
- **Synthetic vendor cohort:** 5 vendor profiles with varying privilege
  levels, MFA posture, and accessible systems — `data/vendors.csv`.
- **Two scenarios, same attacker playbook:** both scenarios run the identical
  scripted sequence (probe → privilege-escalation attempt → lateral movement
  → sensitive-resource attempts → harmless ransomware-marker attempts).
  Only the security configuration differs between scenarios — never the
  attacker's behaviour.
- **Multi-trial benchmark:** 5 vendors × 10 trials × 2 scenarios = **100
  total trials**, fixed random seed (`42`), fully reproducible
  (`src/simulation/engine.py`).
- **Repeated, not independent, trials:** this is **50 repeated simulation
  runs per configuration across 5 synthetic vendor profiles**, not 100
  independent real-world experiments. Seed 42 selects a deterministic
  benign/adversarial mix; every adversarial repetition uses the fixed,
  non-adaptive playbook — see
  `docs/METHODOLOGY.md` Section 12.

## 4. Baseline Environment (Unprotected / Legacy Trust)

```
Compromised vendor -> Authenticated session -> Broad permissions ->
Resource discovery -> Lateral movement -> Sensitive resources ->
Simulated ransomware impact
```

- No MFA required (password-only compromise succeeds).
- Over-privileged RBAC (all 10 banking resources permitted).
- Flat, unsegmented network (any zone reachable from any zone).
- Detection engine disabled.
- No automated containment.

## 5. Protected Environment (Zero-Trust Defensive Controls)

```
Compromised vendor identity
        |
Authenticated session (ASSUMED -- see below)
        v
RBAC / least privilege (vendor-authorized resources only)
        v
Vendor access zone
        v
Attempted lateral movement -> blocked by segmentation / RBAC
        v
Monitoring -> Detection (behavioral + policy-violation rules)
        v
Account / session isolation (automated containment)
        v
Ransomware attempt contained
```

**Key design decision (fixing the original MFA-gate issue):** the main
Protected experiment assumes the compromised identity **already holds an
authenticated session** —
`credential_compromised = True`, `authenticated_session = True`
(`SimulationRunner.run_scenario_2_protected(assume_authenticated_session=True)`,
the default). No credential-theft or MFA-bypass technique is implemented;
this simply sets the starting state so RBAC, segmentation, detection, and
containment — the controls this project studies — are what get evaluated,
rather than every trial terminating at the MFA challenge.

MFA remains part of the architecture and is tested **separately** as its own
standalone control: `assume_authenticated_session=False` exercises the real
MFA challenge, where a credential-only compromise (no second factor) is
correctly blocked before RBAC or segmentation are ever reached. See
`tests/test_simulation.py::test_protected_mfa_gate_blocks_credential_only_compromise`.

## 6. Security Controls

| Control | Module |
| :--- | :--- |
| Authentication / MFA | `src/auth/authentication.py`, `src/auth/mfa.py` |
| RBAC (least privilege) | `src/auth/rbac.py` |
| Network segmentation | `src/network/segmentation.py`, `src/network/access_control.py` |
| Detection (7 deterministic rules) | `src/security/detection.py` |
| Automated containment / session isolation | `src/security/containment.py` |
| Vendor risk scoring (project-specific, not an industry-standard metric) | `src/risk/scoring.py` |

## 7. Metrics

Every metric below is computed from actual simulation runs — never
hardcoded — via `src/metrics/evaluator.py` and `src/simulation/engine.py`:

1. Accessible assets reached during adversarial traversal (`accessible_assets`)
2. Sensitive/backup resources reached (`sensitive_assets_reached`)
3. Internal-zone resources reached (`internal_assets_reached`)
4. Successful lateral-movement steps (`lateral_transitions_successful`)
5. Blocked access attempts (`assets_blocked`)
6. Detection rate (%) on adversarial runs
7. Mean time to first detection and mean time to actionable detection
   (simulated seconds; not operational SOC timing)
8. Containment rate (%)
9. Mean time to contain (MTTC, simulated seconds)
10. Simulated affected files (`files_compromised`, `files_blocked`) on adversarial runs
11. File / data protection rate (%) from actual per-run target counts

## 8. How to Install

Requires Python 3.11+.

```bash
pip install -r requirements.txt
```

## 9. How to Run

Run the full end-to-end simulation (single-vendor live comparison, MFA
standalone check, 100-trial benchmark, metrics, CSV/report/chart export):

```bash
python scripts/run_simulation.py
```

## 10. How to Run Tests

```bash
python -m unittest tests.test_simulation -v
```

## 11. Where Results Are Stored

| Artifact | Path |
| :--- | :--- |
| Raw per-trial records | `results/csv/trial_records.csv` |
| Aggregated comparison metrics | `results/csv/comparison_metrics.csv` |
| Vendor cohort summary | `results/csv/vendors_summary.csv` |
| Sample detection alerts | `results/csv/sample_alerts.csv` |
| Markdown executive summary | `results/summary_report.md` |
| Experiment provenance metadata | `results/experiment_metadata.json` (`source_revision` identifies the base commit and working-tree state used for generation) |
| Publication charts (300 DPI) | `results/charts/*.png` |
| Per-run structured event logs (JSONL) | `logs/*.jsonl` |
| Full methodology, threat model, formulas | `docs/METHODOLOGY.md` |

Re-running `python scripts/run_simulation.py` regenerates all of the above
from a fresh simulation run (fixed seed `42`, fully reproducible).

## 12. Safety & Limitations

- Strictly local, in-memory, synthetic simulation — no real ICICI or banking
  systems, no real customer data, no real credentials, no external network
  calls, no network scanning.
- The "ransomware" component only overwrites and renames dummy files inside
  `data/simulation_workspace/` (rebuilt from `data/` at the start of every
  run) with a harmless marker string — never real encryption, never a real
  destructive payload, never a path outside the project sandbox.
- No credential theft, MFA-bypass technique, or real privilege-escalation
  exploit is implemented; compromise/authentication state is a modeling
  assumption, not a demonstrated technique.

## 13. Experimental Limitations

- **Fixed, non-adaptive attacker playbook** — see Section 3. The seed only
  selects the documented benign/adversarial repetition mix; it does not create
  artificial attacker variation or statistical independence.
- **Vendor risk score is project-specific** (`src/risk/scoring.py`), not an
  industry-standard metric (not CVSS/FAIR/NIST CSF) — used only as an
  internal, explainable comparative measure.
- **Simulated monotonic clock**, not wall-clock or real network timing — see
  `src/security/monitoring.py`.
- Further limitations (host-level filesystem dynamics, IdP integration, the
  benign-session `authenticated` flag quirk, etc.) are documented in
  `docs/METHODOLOGY.md` Section 12.

## Repository Layout

```
src/            Simulation engine, security controls, models, metrics, reporting
scripts/        run_simulation.py -- the single entrypoint
tests/          Unit + integration test suite
data/           Synthetic vendors, banking assets, dummy records
results/        Generated CSVs, markdown report, charts
logs/           Generated per-run JSONL event logs
docs/           Full academic methodology document
AGENTS.md       Instructions for AI coding agents working on this repo
```
