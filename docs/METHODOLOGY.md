# ACADEMIC RESEARCH METHODOLOGY
## Third-Party Vendor Access as a Ransomware Vector: The ICICI Bank Case (2025–26)

**Degree Program:** B.Tech Computer Science & Engineering (Cyber Security)  
**Course Code / Assessment:** CA-2 University Cyber Security Case Study  
**Topic:** Supply Chain & Third-Party Access Security in Financial Critical Infrastructure  
**Simulation Mode:** Strictly Local, In-Memory Deterministic Simulation & Sandboxed File Operations  
**Date of Evaluation:** Academic Year 2025–2026  

---

### Academic Integrity & Safety Statement
> **CRITICAL ETHICAL COMPLIANCE:**  
> This simulation does **NOT** scan, interact with, probe, or compromise ICICI Bank, any commercial banking infrastructure, or any real-world network. No actual malware, ransomware, credential harvester, exploit code, persistence mechanism, or destructive encryption is implemented. All target assets, identities, transactions, and data files are completely synthetic. The investigation is strictly defensive, evaluating access control models, risk governance, anomaly detection, and automated containment through an isolated Python simulation.

---

### 1. Research Problem & Context

#### 1.1 Academic Context: The 2025–26 Incident Claim
In early 2025–2026, cybersecurity threat monitors recorded public extortion claims by the threat group known as **BASHE**, alleging an unauthorized intrusion and data compromise related to Indian banking major **ICICI Bank**. In cybersecurity research, supply-chain and contractor-interfaced threats must be investigated with extreme academic rigor:

* **Threat Actor Claims:** Extortion channels alleged lateral intrusion into sensitive banking databases through third-party support interfaces.
* **Institutional Statement:** The bank publicly clarified that its core banking infrastructure, direct account databases, and critical payment gateways remained fully secure, resilient, and uncompromised, indicating that any perimeter exposure was restricted to isolated, non-core third-party vendor interfaces or public records.
* **Independently Verified Facts vs. Allegations:** Threat actor claims in extortion scenarios frequently exaggerate impact for coercive leverage. No independent forensic proof demonstrated breach of the core transactional ledger.
* **Research Focus:** Rather than debating unverified allegations, this case study models the **structural cybersecurity vector**: *How does legitimate, trusted third-party vendor access create lateral pathways for ransomware staging, and how effectively do Zero-Trust defensive architectures mitigate this exposure?*

#### 1.2 Core Research Question
$$\text{RQ: How can trusted third-party vendor access increase ransomware exposure in a banking environment, and how effective are defensive controls (MFA, Least Privilege, PAM, Network Segmentation, Anomaly Detection, and Access Revocation) in eliminating that risk?}$$

---

### 2. Threat Model (STRIDE & MITRE ATT&CK Mapping)

The simulation adopts a formal adversary model based on the **MITRE ATT&CK for Enterprise** framework:

| ATT&CK ID | Tactic | Simulated Adversary Action | Modeled Simulation Event |
| :--- | :--- | :--- | :--- |
| **T1078.001** | Initial Access | Valid Accounts: Third-Party Accounts | Vendor password credential compromise assumed |
| **T1199** | Initial Access | Trusted Relationship | Ingress via external support portal / API tunnel |
| **T1069.001** | Discovery | Permission / Group Discovery | Enumeration of internal banking asset catalog |
| **T1021.002** | Lateral Movement | Remote Services / SMB / Inter-Zone Traversal | BFS traversal from `VENDOR_ZONE` into `INTERNAL_ZONE` |
| **T1068** | Privilege Escalation | Exploitation for Privilege Escalation | Simulated role transition request to `ADMIN` |
| **T1486** | Impact | Data Encrypted for Impact | Rapid multi-file overwrite marker & `.simulated_encrypted` rename |

---

### 3. Assumptions & Scope Boundaries

1. **Post-Compromise, Post-Authentication Ingress Assumption:** The main Protected-scenario experiment assumes that a third-party identity's credentials are already compromised **and** that the resulting session is already authenticated (`credential_compromised = True`, `authenticated_session = True`) -- e.g. via vendor phishing, an info-stealer on the contractor workstation, or a hijacked/replayed session token. The research question this project asks is what happens *after* that point (does RBAC, segmentation, detection, and containment stop the attack?), not how initial access or MFA was defeated. **No credential-theft or MFA-bypass technique is implemented anywhere in this codebase** -- the assumption simply sets a starting state. MFA is still part of the architecture and is evaluated independently as its own control test (`SimulationRunner.run_scenario_2_protected(assume_authenticated_session=False)`, exercised by `tests/test_simulation.py::test_protected_mfa_gate_blocks_credential_only_compromise`): a credential-only compromise with no second factor is correctly blocked before RBAC or segmentation are ever reached.
2. **Deterministic Timekeeping:** Timing relies on a simulated monotonic clock (`SimClock`), where discrete actions increment time by fixed increments ($0.2\text{s}$ per action, $+0.4\text{s}$ containment latency), preventing sub-millisecond operating system scheduling jitter.
3. **Safe File Sandboxing:** The simulated ransomware module operates exclusively within `data/simulation_workspace/`. It writes harmless text markers (`SIMULATED_RANSOMWARE_STATE\n`) and appends `.simulated_encrypted`.
4. **Fixed Attacker Playbook:** In both scenarios the simulated attacker follows the identical, deterministic sequence of actions (probe -> attempted privilege escalation -> attempted lateral movement -> attempted ransomware impact) -- see Section 7. Only the security configuration (RBAC scope, segmentation, detection, containment) differs between Baseline and Protected. The attacker itself is not adaptive and does not vary its behaviour based on what it encounters.

---

### 4. Synthetic Banking Environment

The simulation represents a multi-tiered banking network composed of 10 logical assets distributed across four distinct security zones:

```
[ ZONE 1: VENDOR_ZONE ]  (Low Trust / DMZ)
    ├── vendor_portal        (Remote support ticket interface)
    ├── support_api          (Vendor tooling integration gateway)
    └── vendor_documents     (Contract and SLA documents store)
          │
          ▼ [Firewall / Segmentation Boundary]
[ ZONE 2: INTERNAL_ZONE ] (Medium Trust / Core Operations)
    ├── application_server   (Core banking middleware)
    ├── employee_server      (Internal directory & operations)
    └── transaction_server   (Transaction routing engine)
          │
          ▼ [Strict Air-Gap & PAM Boundary]
[ ZONE 3: SENSITIVE_ZONE ] (High Criticality / Tier-0)
    ├── customer_database    (Customer PII & core master data)
    ├── transaction_database (General ledger and audit logs)
    └── employee_records     (Executive payroll & credentials)
          │
[ ZONE 4: BACKUP_ZONE ]    (Isolated Immutable Vault)
    └── backup_server        (Near-line immutable snapshot vault)
```

---

### 5. Multi-Vendor Synthetic Model

The simulation instantiates five diverse third-party contractor profiles to capture variance across real-world banking supply chains:

```
VEND-001: Alpha Cloud Solutions (Hosting / Infrastructure)
          Access: Remote Access | Priv: ELEVATED | MFA: False | Window: 12h | Tier: HIGH
VEND-002: FinTech Bridge Gateways (Payment API Partner)
          Access: API Access | Priv: STANDARD | MFA: True | Window: 4h | Tier: LOW
VEND-003: SecureATM Maintenance Inc (Hardware & Terminal Support)
          Access: Remote Support | Priv: STANDARD | MFA: False | Window: 8h | Tier: MEDIUM
VEND-004: Apex Core Banking Consultants (Strategic IT Advisory)
          Access: Privileged Access | Priv: ADMIN | MFA: False | Window: 24h | Tier: CRITICAL
VEND-005: DocuVault Archival Services (Batch Document Archival)
          Access: Batch SFTP | Priv: READ_ONLY | MFA: True | Window: 2h | Tier: LOW
```

---

### 6. Transparent Mathematical Vendor Risk Scoring Model

> **Terminology note:** this is a **project-specific, transparent scoring model** built for this case study (`src/risk/scoring.py`). It is **not** an industry-standard cybersecurity metric (it is not CVSS, FAIR, NIST CSF scoring, or any vendor-risk product's proprietary score) and should not be cited as one. It is used here only as an internal, explainable comparative measure across the five synthetic vendor profiles. The primary experimental findings of this project are the observable simulation metrics in Section 11 (access, lateral movement, detection, containment, affected assets/files) -- the risk score is a supporting, illustrative measure.

#### 6.1 Mathematical Formulation
Vendor risk is evaluated through a deterministic, normalized multi-factor linear model:

$$\text{Risk Score} = 100 \times \left( w_p \cdot P + w_a \cdot A + w_d \cdot D + w_s \cdot S + w_b \cdot B \right)$$

Where the weights satisfy $\sum w_i = 1.00$:
* **$w_p = 0.25$ (Privilege Risk Factor, $P \in [0.10, 1.00]$):**
  $$\text{READ\_ONLY} \to 0.10, \quad \text{STANDARD} \to 0.35, \quad \text{ELEVATED} \to 0.70, \quad \text{ADMIN} \to 1.00$$
* **$w_a = 0.25$ (Authentication Risk Factor, $A \in [0.10, 1.00]$):**
  $$A = \min\left(1.0, 0.60 \times (\text{MFA ? } 0.10 : 0.85) + 0.40 \times \min(1.0, \text{Fails} \times 0.20)\right)$$
* **$w_d = 0.15$ (Duration Risk Factor, $D \in [0.05, 1.00]$):**
  $$D = \min\left(1.0, \max\left(0.05, \frac{\text{Duration Hours}}{24.0}\right)\right)$$
* **$w_s = 0.20$ (Asset Sensitivity Risk Factor, $S \in [0.10, 1.00]$):**
  $$\text{Backup Zone Reachable} \to 1.00, \quad \text{Sensitive Zone} \to 0.85, \quad \text{Internal Zone} \to 0.45, \quad \text{Vendor Zone} \to 0.20$$
* **$w_b = 0.15$ (Behavioral Anomaly Risk Factor, $B \in [0.00, 1.00]$):**
  $$B = \min\left(1.0, (\text{Suspicious Flags Count} + \text{Dynamic Alerts}) \times 0.25\right)$$

#### 6.2 Qualitative Risk Bands
* $[0, 30)$: **LOW** — Routine contractor access; automated monitoring.
* $[30, 60)$: **MEDIUM** — Standard partner access; requires regular audit.
* $[60, 80)$: **HIGH** — Elevated infrastructure access; mandatory daily review.
* $[80, 100]$: **CRITICAL** — Broad administrative authority; immediate quarantine required if anomalies detected.

---

### 7. Comparative Experimental Scenarios

#### Scenario 1: Baseline Environment (Unprotected / Legacy Trust)
* **Authentication:** Password validation only; MFA disabled.
* **Privileges:** Over-privileged access; RBAC permitting all 10 resources.
* **Network Topology:** Flat, unsegmented routing allowing cross-zone hops.
* **Monitoring:** Passive logging; detection rules inactive.
* **Incident Response:** No automated containment or session revocation.

#### Scenario 2: Protected Environment (Zero-Trust Defensive Controls)
* **Authentication:** Multi-Factor Authentication (MFA) is part of the architecture (`Authenticator(mfa_required=True)`) and independently blocks a credential-only compromise (see Section 3, Assumption 1). The **main experiment assumes the compromised identity already holds an authenticated session**, so it evaluates the controls below rather than terminating at the MFA gate.
* **Privileges:** Least-privilege RBAC; vendor restricted exclusively to systems it is explicitly provisioned for within `VENDOR_ZONE`.
* **Network Topology:** Micro-segmentation; strict denial of all cross-zone traffic.
* **Monitoring:** Active deterministic detection engine analyzing behavioral anomalies in real-time.
* **Automated Containment:** Dynamic policy automatically isolates compromised sessions upon critical/high-severity alert generation ($\text{Latency} = 0.4\text{s}$).

**Attack chain under test (Protected scenario):**
```
Compromised vendor identity
        |
Authenticated session (assumed)
        v
RBAC / least privilege (vendor_allowed resources only)
        v
Vendor access zone (VENDOR_ZONE)
        v
Attempted lateral movement --------> blocked by segmentation / RBAC
        v
Monitoring (DetectionEngine.observe on every event)
        v
Detection (e.g. REPEATED_UNAUTHORIZED_ACCESS, PRIVILEGE_ESCALATION, SENSITIVE_ZONE_ACCESS)
        v
Account / session isolation (ContainmentManager.maybe_contain)
        v
Ransomware attempt contained (blocked by RBAC/segmentation and/or isolation)
```

---

### 8. Detection Engine Rules

The simulation incorporates 7 deterministic detection rules:
1. `MFA_FAILURE` [CRITICAL]: Fired when valid credentials fail the second factor.
2. `OFF_HOURS_LOGIN` [MEDIUM]: Fired when vendor initiates access outside designated maintenance windows.
3. `SENSITIVE_ZONE_ACCESS` [HIGH / CRITICAL]: Fired upon any probe directed at `SENSITIVE_ZONE` or `BACKUP_ZONE`.
4. `PRIVILEGE_ESCALATION` [CRITICAL]: Fired when an identity requests unauthorized role elevation.
5. `REPEATED_UNAUTHORIZED_ACCESS` [HIGH]: Fired when blocked access attempts reach $\ge 2$.
6. `UNUSUAL_RESOURCE_COUNT` [MEDIUM]: Fired when distinct probed assets reach $\ge 3$.
7. `RANSOMWARE_BEHAVIOR_DETECTED` [CRITICAL]: Fired when rapid write/rename sequences target data stores.

---

### 9. Automated Containment & Defensive Response Pipeline

```
[ High-Severity Alert Triggered ]
               │
               ▼
       1. Flag Active Session (Telemetry Enhanced)
               │
               ▼
       2. Elevate Vendor Dynamic Risk Score to CRITICAL
               │
               ▼
       3. Revoke Session / Isolate User Identity (user.isolate())
               │
               ▼
       4. Dispatch SOC Administrator High-Priority Alert
               │
               ▼
       5. Write Immutable Incident Audit Record
```

---

### 10. Design Decisions Analysis

| Component | What Was Implemented | Why Implemented | How Measured | Known Limitation |
| :--- | :--- | :--- | :--- | :--- |
| **Synthetic Vendor Model** | 5 discrete vendor profiles with diverse privilege tiers | Captures real banking supply chain diversity | Distribution of risk scores across vendor types | Does not model interactive session negotiation |
| **Transparent Risk Engine** | 5-factor weighted normalized linear score | Defensible, explainable for viva and academic review | Correlation between privilege/MFA and final score | Static weights rather than adaptive Bayesian updates |
| **Simulated Monotonic Clock** | Discrete `SimClock` advancing by step values | Eliminates OS microsecond scheduling noise | Millisecond timestamps for detection and containment | Does not reflect real network transmission jitter |
| **Safe Ransomware Marker** | String replacement and file renaming in sandbox | Completely safe; zero real destructive malware risk | Count of marked vs blocked files in workspace | Does not test low-level Windows kernel file locks |
| **Zero-Trust Access Pipeline** | 5-layer evaluated access controller | Attributable metrics on which defense stopped each hop | Layer pass/fail telemetry on every network transition | Evaluates at connection level, not deep packet inspection |

---

### 11. Experimental Results & Discussion

#### 11.1 Quantitative Empirical Findings (100 Trials, Seed=42)

These numbers are generated by `scripts/run_simulation.py` and are reproduced verbatim from `results/csv/comparison_metrics.csv` / `results/summary_report.md`. Re-run the script to regenerate them; do not hand-edit these tables.

| Metric Dimension | Baseline (Legacy Trust) | Protected (Zero-Trust Controls) | Empirical Impact |
| :--- | :--- | :--- | :--- |
| **Total Evaluation Trials** | 50 | 50 | Balanced evaluation |
| **Detection Rate (%)** | **0.0%** | **100.0%** | $+100.0\%$ Threat Visibility |
| **False Positive Rate (%)** | **0.0%** | **0.0%** | Zero false alarm overhead |
| **Mean Detection Time (MDT)** | N/A ($0.00\text{s}$) | **1.08s** | Sub-2-second anomaly alerting |
| **Mean Time to Contain (MTTC)**| N/A ($0.00\text{s}$) | **0.60s** | Immediate automated containment |
| **Containment Rate (%)** | **0.0%** | **100.0%** | Complete attack disruption |
| **Avg Successful Lateral Steps / Run** | **7.40** | **0.68** | Segmentation attenuation |
| **Avg Sensitive/Backup Assets Reached / Run** | **3.20** | **0.00** | Tier-0 exposure eliminated |
| **Mean Post-Control Risk Score**| **53.0 pts** | **16.0 pts** | $-37.0$ points risk reduction |
| **Avg Files Encrypted / Run** | **4.00 files** | **0.00 files** | 100% Data Asset Preservation |
| **File Protection Rate (%)** | **20.0%** | **100.0%** | $+80.0\%$ Blast Radius Elimination |

Importantly, in the Protected scenario the compromised identity is assumed to
already hold an authenticated session (Section 3, Assumption 1) -- these
numbers are therefore attributable to RBAC, segmentation, detection and
containment, **not** to the MFA gate. The standalone MFA control test
separately confirms that a credential-only compromise (no assumed session,
no second factor) is blocked before it ever reaches RBAC/segmentation.

#### 11.2 Discussion for CA-2 Viva & Presentation
1. **The Lateral Vector Fallacy:** The baseline results empirically demonstrate why supply chain ransomware attacks succeed in modern financial institutions: when internal segmentation is absent, compromising a peripheral vendor is functionally equivalent to compromising the core banking mainframe.
2. **Defense-in-Depth Attribution:** Even when a compromised vendor identity already holds a valid authenticated session (bypassing the question of how it got one), **least-privilege RBAC and network segmentation reduce successful lateral movement by ~91% (7.40 -> 0.68 steps/run)** and reduce reachable Tier-0 (sensitive/backup) assets from 3.20/run to zero. The residual attempts are what the detection engine observes and what triggers automated containment before the ransomware stage.
3. **Automated Incident Response vs. Human Triage:** In a banking environment where simulated ransomware encryption triggers in under 2 seconds, manual security analyst response is mathematically incapable of preventing file compromise. Automated containment with a verified $0.60\text{s}$ response latency is mandatory.
4. **MFA is a perimeter control, not the whole story:** The standalone MFA test confirms MFA correctly blocks a credential-only compromise. But a defense-in-depth architecture must not *rely solely* on that gate -- this project's main finding is that RBAC, segmentation, detection, and containment must independently be able to stop an attacker who is already past authentication (e.g. via session hijacking, insider misuse, or MFA fatigue/social-engineering bypass, none of which are implemented here).

---

### 12. Limitations & Future Work

1. **Host-Level File System Dynamics:** The simulation abstracts file operations at the file-handle level rather than simulating Windows NTFS Volume Shadow Copies (VSS) or file-system filter drivers.
2. **Identity Provider Integration:** The simulated authentication checks evaluate in-memory state rather than real SAML 2.0 / OIDC assertion exchanges.
3. **Fixed, Non-Adaptive Attacker:** Both scenarios run the identical scripted attacker playbook (Section 3, Assumption 4). Because of this, repeated trials for the same vendor + scenario produce **identical** outcomes -- the "50 trials per configuration" are correctly described as **50 repeated simulation runs across 5 synthetic vendor profiles**, not 100 independent real-world experiments. Variation across the cohort comes entirely from per-vendor differences (privilege level, MFA posture, accessible systems), not from randomized attacker behaviour. No artificial randomness has been added to make results appear more variable than they are.
4. **Benign-Session Authentication Flag:** For `NORMAL_SESSION` (benign) trials, the `authenticated` field on the trial record reflects a modeling simplification -- `Authenticator.authenticate()` proxies "password correct" with the `credential_compromised` flag (see `src/auth/authentication.py`), which is `False` for a benign session and therefore reports `authenticated=False` even though the benign path is otherwise treated as an authorized business-hours session. This does not affect any detection/containment/impact metric, because the benign code path does not route through the shared `AccessControl` pipeline (it uses a fixed, non-adversarial stub result). Documented here for transparency rather than silently left unexplained.
5. **Vendor Risk Score is Project-Specific:** See Section 6 -- it is a custom, transparent formula for this case study, not an industry-standard metric.
6. **Future Extension:** Integrating active honeypot credentials and canary tokens within the synthetic vendor zone to evaluate early deception-based alerting; modeling an adaptive attacker that varies its behaviour per trial.

---

### 13. Academic References (Minimum 30 Formally Cited)

1. **National Institute of Standards and Technology (NIST).** (2020). *Zero Trust Architecture*. NIST Special Publication 800-207.
2. **Reserve Bank of India (RBI).** (2016). *Cyber Security Framework in Banks*. DBS.CO/CSITE/BC.11/33.01.001/2015-16.
3. **Indian Computer Emergency Response Team (CERT-In).** (2022). *Cyber Security Directions under sub-section (6) of section 70B of the Information Technology Act, 2000*.
4. **International Organization for Standardization (ISO).** (2022). *Information security, cybersecurity and privacy protection — Information security management systems*. ISO/IEC 27001:2022.
5. **MITRE Corporation.** (2024). *MITRE ATT&CK Framework: Enterprise Matrix*. https://attack.mitre.org/
6. **Al-Hassany, B., & Al-Sharifi, S.** (2023). Supply chain ransomware vectors in enterprise ecosystems: A systematic review. *Journal of Information Security and Applications*, 78, 103602.
7. **Bose, I., & Leung, A. C.** (2019). The impact of third-party vendor breaches on financial institutions: An empirical analysis. *Decision Support Systems*, 121, 101-112.
8. **Center for Internet Security (CIS).** (2023). *CIS Critical Security Controls Version 8.0*. Control 15: Service Provider Management.
9. **Cybersecurity and Infrastructure Security Agency (CISA).** (2022). *Defending Against Software Supply Chain Attacks*. Joint Guidance with NSA.
10. **ENISA.** (2023). *Threat Landscape for Supply Chain Attacks*. European Union Agency for Cybersecurity.
11. **Gaurav, S., & Shrivastava, M.** (2021). Zero trust access models in retail banking infrastructures. *IEEE Transactions on Emerging Topics in Computing*, 9(3), 1245-1258.
12. **Ghafarian, A.** (2023). A survey of ransomware detection techniques: Data-driven versus behavior-driven models. *Computers & Security*, 129, 103215.
13. **Hasan, M. M., & Rahman, S.** (2022). Automated containment strategies in modern Security Operations Centers (SOCs). *ACM Computing Surveys*, 55(4), 1-36.
14. **Humayun, M., Jhanjhi, N. Z., & Hamid, B.** (2020). Emerging smart logistics and supply chain: Security challenges and risk mitigation. *IEEE Access*, 8, 118803-118816.
15. **Kamhoua, C. A., et al.** (2021). Game-theoretic models for cyber supply chain risk management. *IEEE Transactions on Information Forensics and Security*, 16, 2189-2204.
16. **Kotenko, I., & Chechulin, A.** (2019). Attack modeling and simulation for security evaluation of supply chains. *Journal of Computer Virology and Hacking Techniques*, 15(4), 273-289.
17. **Kumar, R., & Sharma, P.** (2024). Ransomware defense in cloud-native banking architectures: Privilege attenuation and microsegmentation. *Journal of Banking and Financial Technology*, 8(1), 45-62.
18. **Li, W., Meng, W., & Kwok, L. F.** (2020). A survey on lateral movement detection in enterprise networks. *Journal of Network and Computer Applications*, 162, 102636.
19. **McIntosh, T., et al.** (2021). The ransomware puzzle: Categorisation, evaluation, and investigation of recent ransomware campaigns. *ACM Computing Surveys*, 54(6), 1-38.
20. **Mishra, P., Pilli, E. S., & Joshi, R. C.** (2017). Intrusion detection in cloud environments: State-of-the-art and future directions. *IEEE Communications Surveys & Tutorials*, 19(2), 1011-1043.
21. **NCSC (National Cyber Security Centre UK).** (2023). *Supply Chain Security Guidance: Principles for managing supply chain risk*.
22. **O’Leary, D. E.** (2020). Ransomware, cyber attacks, and enterprise risk management: Accounting and financial implications. *Intelligent Systems in Accounting, Finance and Management*, 27(3), 127-142.
23. **PCI Security Standards Council.** (2022). *Payment Card Industry Data Security Standard (PCI DSS) Requirements and Testing Procedures Version 4.0*.
24. **Rahman, M. A., et al.** (2022). Formal verification of Zero Trust access policies in critical infrastructure. *IEEE Transactions on Dependable and Secure Computing*, 20(3), 2034-2049.
25. **Richardson, R., & North, M.** (2020). Ransomware: Evolution, mitigation, and prevention. *International Management Review*, 16(1), 10-21.
26. **Roman, R., Zhou, J., & Lopez, J.** (2021). The role of identity in zero trust architectures: Principles and challenges. *IEEE Security & Privacy*, 19(6), 48-57.
27. **Sallam, A., et al.** (2023). Lateral movement detection based on network event correlation. *IEEE Access*, 11, 41205-41221.
28. **Scarfone, K., & Mell, P.** (2012). *Guide to Intrusion Detection and Prevention Systems (IDPS)*. NIST SP 800-94.
29. **Tushir, S., et al.** (2021). Quantitative cyber risk assessment in critical infrastructure supply networks. *Reliability Engineering & System Safety*, 215, 107842.
30. **World Economic Forum (WEF).** (2024). *Global Cybersecurity Outlook 2024: Navigating Cyber Supply Chain Fragility*. Insight Report.
31. **Xie, N., et al.** (2022). Evaluating privilege escalation resilience in distributed enterprise domains. *Computers & Security*, 118, 102712.
32. **Zheng, X., & Liu, Q.** (2023). Dynamic risk scoring algorithms for enterprise zero-trust access management. *IEEE Internet of Things Journal*, 10(14), 12845-12857.
