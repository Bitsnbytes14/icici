# CA-2 Experimental Results & Findings

## Academic Case Study: Third-Party Vendor Access as a Ransomware Vector
**Target Institutional Context:** Banking Environment (Inspired by 2025–26 Threat Claims)  
**Safety Protocol:** Strictly Safe In-Memory Simulation & Sandboxed File Markers  
**Random Seed:** 42 (Fully Reproducible)

---

### 1. Comparative Performance Summary

| Metric Dimension | Baseline (Legacy Trust) | Protected (Zero-Trust Controls) | Improvement / Delta |
| :--- | :--- | :--- | :--- |
| **Total Multi-Vendor Trials** | 50 | 50 | Identical cohort size |
| **Detection Rate (%)** | 0.0% | 100.0% | **+100.0%** |
| **False Positive Rate (%)** | 0.0% | 0.0% | 0.0% (Low friction) |
| **Mean Detection Time (s)** | 0.0s | 1.08s | Fast anomaly triage |
| **Mean Time to Contain (s)** | 0.0s | 0.6s | Rapid automated isolation |
| **Containment Rate (%)** | 0.0% | 100.0% | **+100.0%** |
| **Mean Pre-Control Risk Score** | 44.0 | 44.0 | Identical baseline posture |
| **Mean Post-Control Risk Score** | 53.0 | 16.0 | **-37.0 pts** |
| **Relative Risk Reduction (%)** | -20.5% | 63.6% | **+63.6%** |
| **Avg Assets Compromised / Run** | 8.2 | 1.32 | Reduced lateral spread |
| **Avg Successful Lateral Steps / Run** | 7.4 | 0.68 | Segmentation attenuation |
| **Avg Sensitive/Backup Assets Reached** | 3.2 | 0.0 | Tier-0 exposure |
| **Avg Files Encrypted / Run** | 4.0 | 0.0 | Blast radius halted |
| **File Protection Rate (%)** | 20.0% | 100.0% | **+80.0%** |

---

### 2. Key Academic Findings for Report Discussion

**Experimental configuration note:** the Protected scenario below models a vendor
identity that has **already compromised credentials and holds an authenticated
session** (`credential_compromised = True`, `authenticated_session = True`) --
the research question is what happens *after* that point, not whether MFA can
be defeated. MFA remains part of the architecture and is evaluated separately
as a standalone control test (see `docs/METHODOLOGY.md` and
`tests/test_simulation.py::test_protected_mfa_gate_blocks_credential_only_compromise`),
where a credential-only compromise with no second factor is correctly blocked
before it ever reaches RBAC or segmentation.

1. **Ransomware Vector Elimination via Defense-in-Depth:**
   - In the baseline environment, a single compromised vendor credential allowed full traversal from `vendor_portal` across internal tiers to `customer_database` and `backup_server`, resulting in an average of **4.0 files marked as encrypted** per run.
   - Under Zero-Trust controls, an *already-authenticated* compromised session was still confined by least-privilege RBAC and strict zone segmentation, which limited lateral movement to **0.68 successful hop(s)/run** and **0.0 sensitive/backup asset(s) reached/run** on average -- yielding a **100.0% file protection rate** once detection and automated containment isolated the session.

2. **Automated Incident Response vs Lateral Traversal:**
   - Active detection identified anomalies within **1.08s** and triggered automated session isolation in **0.6s**, halting lateral movement before sensitive data stores could be enumerated.

3. **Vendor Risk Scoring Governance:**
   - The multi-factor scoring model effectively differentiated low-privilege contractors from high-privilege administrators. This is a project-specific, transparent scoring model (see `docs/METHODOLOGY.md` Section 6) -- not an industry-standard cybersecurity metric.
   - Enforcing Just-in-Time (JIT) access windows and least-privilege RBAC reduced average vendor risk exposure by **63.6%**.

4. **Repeated vs. independent trials:** each configuration is evaluated over **50 repeated simulation runs** (5 synthetic vendor profiles x 10 runs each, seed=42). The attacker follows a fixed, deterministic playbook (probe -> attempted privilege escalation -> attempted lateral movement -> attempted ransomware impact) per vendor, so repeated runs for the same vendor produce identical outcomes; per-vendor variation (privilege level, MFA posture, accessible systems) is what drives the differences seen across the cohort. These are **50 repeated simulation runs per configuration**, not 100 independent real-world experiments.

---

### 3. Generated Visualizations for CA Report

- `results/charts/fig1_vendor_risk_comparison.png`: Risk Score before and after defensive controls.
- `results/charts/fig2_detection_containment_efficacy.png`: Detection and containment percentage rates.
- `results/charts/fig3_response_timing_profile.png`: Mean detection time vs containment latency.
- `results/charts/fig4_blast_radius_mitigation.png`: Asset and file blast radius comparison.
- `results/charts/fig5_defense_in_depth_layers.png`: Proportion of attacks blocked at each control layer.
