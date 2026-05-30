# Structural Recurrence Detection Framework

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20467943.svg)](https://doi.org/10.5281/zenodo.20467943)


**Detecting Non-Periodic Deterministic C2 Scheduling via Algebraic Recurrence Analysis**

A structural detection framework for command-and-control beaconing that uses deterministic non-periodic timing — Fibonacci, Tribonacci, Padovan, Narayana recurrence schedules, and bounded irrational rotation. These scheduling families evade RITA-style periodicity scoring by design while remaining structurally identifiable via multi-gate recurrence testing.

> "A beacon does not need to be periodic to be structured."

**Andre Cordero** — RepoSignal.io LLC

---

## Key Results

- **Ceiling Theorem**: RITA-style composite scoring has a provable structural blind spot for growing-interval schedules (max score 0.50 + 0.50/n, below the 0.70 alert threshold for n ≥ 3)
- **22 structural activations** across 145,406 labeled background flows (CTU-13 + Stratosphere datasets, n ≥ 8)
- **Zero activations** on 3,165 labeled botnet flows
- **Zero false positives** on the four most common retry/backoff patterns (binary, AWS SDK, Kubernetes, TCP retransmission)

---

## Validated Detectors

| Detector | Family | Growth Regime | Signal Type |
|----------|--------|--------------|-------------|
| Beacon Hunter v0.3.0 | Fibonacci (φ ≈ 1.618) | Exponential | Additive recurrence |
| Tribonacci Hunter v1.1 | Tribonacci (τ ≈ 1.839) | Exponential | Additive recurrence |
| Padovan Hunter v1.1 | Padovan (ρ ≈ 1.325) | Exponential | Additive recurrence |
| Narayana Hunter v1.1 | Narayana (N ≈ 1.466) | Exponential | Additive recurrence |
| Bounded Hunter v1.0 | Irrational rotation | Bounded | Three-gap theorem |
| Reverse Scanner v1.2 | All four recurrence families | — | Bidirectional extension (wraps recurrence detectors in reverse-order pass) |

All detectors use a multi-gate architecture:
- **Gate 1**: Ratio/growth pre-filter (computationally inexpensive)
- **Gate 2**: Structural confirmation with permutation significance testing
- **Gate 2.5**: Convergence-based geometric-backoff rejection

---

## Quick Start

```bash
git clone https://github.com/mrcord77/recurrence-detection-framework.git
cd recurrence-detection-framework
pip install -r requirements.txt

# Run the detection gap demonstration
python demo.py
```

### Demo Output

```
  Family           n  RITA Score  Ceiling  Alert?  Detector Result                  Conf
  fibonacci       20  ✗    56.4%    52.5%      no  ✓ ADDITIVE_RECURRENCE_BEACON    83.3%
  tribonacci      15  ✗    55.3%    53.3%      no  ✓ TRIBONACCI_RECURRENCE_BEACON  73.8%
  padovan         20  ✗    46.7%    52.5%      no  ✓ PADOVAN_RECURRENCE_BEACON     83.3%
  narayana        20  ✗    52.0%    52.5%      no  ✓ NARAYANA_RECURRENCE_BEACON    73.4%
  rotation        30  ✗    40.9%    51.7%      no  ✓ ROTATION_BEACON               21.1%

  RITA-style scoring: 5/5 schedules score below alert threshold
  Structural detectors: 5/5 schedules detected

  ✓ DETECTION GAP CONFIRMED
```

**Verified with RITA v5.1.2:** A 20-connection Fibonacci beacon scored 45.9% (Severity: None). Beacon Hunter classified the same flow as ADDITIVE_RECURRENCE_BEACON at 86.1% confidence.

Generate Zeek conn.logs for RITA import:

```bash
python demo.py --zeek
# Then: rita import --logs demo_logs --database demo_test
```

### Run a single detector on a Zeek conn.log

```python
from detectors.beacon_hunter.detectors import classify_flow

# timestamps = list of connection timestamps for a single flow
result = classify_flow(timestamps, connection_level=True, min_pkts=7)
print(result["classification"])  # ADDITIVE_RECURRENCE_BEACON or BACKGROUND
```

### Run all detectors on a Zeek conn.log

```python
import importlib

DETECTORS = [
    ("Beacon Hunter",     "detectors.beacon_hunter.detectors"),
    ("Tribonacci Hunter", "detectors.tribonacci_hunter.detectors"),
    ("Padovan Hunter",    "detectors.padovan_hunter.detectors"),
    ("Narayana Hunter",   "detectors.narayana_hunter.detectors"),
    ("Bounded Hunter",    "detectors.bounded_hunter.detectors"),
]

for name, module_path in DETECTORS:
    mod = importlib.import_module(module_path)
    result = mod.classify_flow(timestamps, connection_level=True, min_pkts=7)
    if result["classification"] != "BACKGROUND":
        print(f"{name}: {result['classification']} (conf={result['confidence']:.2f})")
```

### Run the Reverse Scanner (bidirectional)

```python
from detectors.reverse_scanner.detectors import classify_flow

result = classify_flow(timestamps, connection_level=True, min_pkts=7)
# Returns direction: FORWARD or REVERSE
print(f"{result['classification']} ({result['direction']})")
```

---

## Evidence Hardening Tests

Reproducible validation scripts confirm all major paper claims:

```bash
# Run all tests in one shot (~12 seconds)
PYTHONPATH=. python3 run_all_tests.py
```

| Test | What it verifies | Paper section |
|------|-----------------|---------------|
| Test 1 (RITA ceiling) | Ceiling theorem is valid and conservative; skew+bimodal anti-correlated for growing sequences | Section 4.2 |
| Test 2 (Injection) | 5/5 beacons detected, 0/5 RITA alerts, 0/200 background FP in mixed corpus | Section 8.1 |
| Test 3 (n-sensitivity) | n≥8 threshold empirically justified; 0% detection at n=6, 100% at n=8 for three families | Section 8.4 |
| Test 5 (Gate 2.5 cost) | 78% detection at 10% jitter, 50% at 20% jitter; all misses from Gate 2.5 | Section 8.7 |
| Test 6 (Multi-method) | 0/100 alerts across RITA, CV, Lomb-Scargle, FFT vs all 5 families × 5 jitter levels | Section 8.10 |

Individual scripts are in `validation/` for standalone use.

**Note on Gate 2.5 (Test 5):** The paper previously described recurrence detector jitter tolerance as "robust to 15–20%." The 100-seed sweep shows 78% detection at 10% jitter and 50% at 20% jitter for Fibonacci (n=20). This is a documented calibration trade-off between backoff rejection and true-positive rate. Section 8.7 of the paper has been corrected with empirical rates.

## Validation

### CTU-13 Large-Scale Validation

```bash
cd validation
python validate_ctu13_core.py      # Config A: 5 individual detectors
python validate_ctu13_reverse.py   # Config B: Reverse Scanner + Bounded
```

Requires CTU-13 dataset: https://www.stratosphereips.org/datasets-ctu13

### Backoff Stress Test

```bash
cd validation
python backoff_test_battery.py
```

Tests 8 common retry/backoff patterns (binary, AWS SDK, Kubernetes, TCP, gRPC, browser, CDN, mobile) against all detectors.

### Synthetic Multi-Week Traffic

```bash
cd validation
python generate_multiweek_traffic.py
```

Generates 970 flows across 10 realistic enterprise traffic types and tests all detectors.

---

## Repository Structure

```
recurrence-detection-framework/
├── LICENSE                          # AGPL-3.0
├── README.md
├── requirements.txt
├── demo.py                          # Detection gap demonstration
├── detectors/
│   ├── beacon_hunter/               # Fibonacci (φ ≈ 1.618)
│   │   └── detectors.py
│   ├── tribonacci_hunter/           # Tribonacci (τ ≈ 1.839)
│   │   └── detectors.py
│   ├── padovan_hunter/              # Padovan (ρ ≈ 1.325)
│   │   └── detectors.py
│   ├── narayana_hunter/             # Narayana (N ≈ 1.466)
│   │   └── detectors.py
│   ├── bounded_hunter/              # Irrational rotation
│   │   └── detectors.py
│   └── reverse_scanner/             # Bidirectional recurrence (v1.2)
│       └── detectors.py
├── validation/
│   ├── validate_ctu13_core.py       # Config A: individual detectors
│   ├── validate_ctu13_reverse.py    # Config B: reverse scanner + bounded
│   ├── backoff_test_battery.py      # Retry/backoff confounder testing
│   ├── spectral_comparison.py       # Rayleigh periodogram analysis
│   └── generate_multiweek_traffic.py
└── paper/
    ├── framework_paper_final.docx   # Full paper
    └── framework_paper_draft.md     # Markdown source
```

---

## Taxonomy

The framework identifies four growth regimes for deterministic non-periodic scheduling:

| Growth Regime | Example | Detection Status |
|--------------|---------|-----------------|
| **Exponential** | Fibonacci, Tribonacci, Padovan, Narayana | ✅ Validated (22 activations / 145K flows) |
| **Bounded** | Irrational rotation (three-gap theorem) | ✅ Validated (3 activations / 145K flows) |
| **Logarithmic** | Consecutive primes | ⬜ Open research problem |
| **Polynomial** | Power-law growth (n², n³) | ⬜ Open research problem |

The logarithmic and polynomial regimes are identified in the taxonomy but do not have validated detection methods. Current approaches for these regimes test individual interval values rather than inter-interval relationships, producing unacceptable false-positive rates at scale. Developing relational detection signals for these regimes is an open research problem.

---

## Paper

**"A Structural Detection Framework for Non-Periodic Deterministic C2 Scheduling: Taxonomy, Ceiling Proof, and Family-Specific Detectors"**

Andre Cordero, RepoSignal.io LLC

The full paper is available in `paper/framework_paper_final.docx`.

Key contributions:
1. **Structural ceiling proof** for RITA-style composite scoring on growing schedules
2. **Growth-regime taxonomy** of non-periodic deterministic scheduling families
3. **Algebraic recurrence enumeration** — closed classification of binary-coefficient recurrences up to third order
4. **Multi-gate detection architecture** with convergence-based backoff rejection
5. **Large-scale validation** on CTU-13 (145K+ flows, 22 structural activations)
6. **Three-gap theorem application** to network security detection

---

## Threat Model

These scheduling families are operationally attractive to adversaries because they are trivial to implement (1–3 lines of code), fully deterministic (the attacker knows every future callback time), and produce intervals with no dominant period, no modal interval, and high variance.

**No confirmed real-world malware is known to use these scheduling families.** The framework addresses a plausible future threat based on operational incentive analysis, not a confirmed current one.

---

## Citation

If you use this work, please cite:

```bibtex
@article{cordero2026structural,
  title={A Structural Detection Framework for Non-Periodic Deterministic C2 Scheduling},
  author={Cordero, Andre},
  year={2026},
  note={RepoSignal.io LLC}
}
```

---

## Related Work

- [Beacon Hunter](https://github.com/mrcord77/beacon-hunter) — the original Fibonacci-only detector (predecessor to this framework)
- [RITA](https://github.com/activecm/rita) — Real Intelligence Threat Analytics
- [Cobalt Strike](https://www.cobaltstrike.com/) — C2 framework with malleable timing profiles

---

## License

GNU Affero General Public License v3.0 (AGPL-3.0)

See [LICENSE](LICENSE) for the full text.

Commercial licensing available through RepoSignal.io LLC.
