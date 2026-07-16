# Structural Recurrence Detection Framework

Detects structured C2 beacons in network traffic that evade RITA-style periodicity detectors.

Standard beacon detectors (RITA) use composite periodicity scoring (skew, bimodality, top-cover, streak). This scoring has a provable ceiling of `0.50 + 0.50/n` for any schedule with n distinct growing intervals — always below the 0.70 alert threshold for n >= 3. An adversary using deterministic non-periodic schedules (Fibonacci, Tribonacci, Padovan, Narayana, irrational rotation) evades RITA while remaining structurally detectable via algebraic recurrence analysis.

**Verified result (RITA v5.1.2, May 2026):** A 20-connection Fibonacci beacon scored 45.9% in RITA (Severity: None). Beacon Hunter classified the same flow as ADDITIVE_RECURRENCE_BEACON at 86.1% confidence.

## Detectors

| Detector | Target Recurrence | Algebraic Constant | Classification |
|---|---|---|---|
| Beacon Hunter v0.3.0 | F(n) = F(n-1) + F(n-2) | phi = 1.618... | ADDITIVE_RECURRENCE_BEACON |
| Tribonacci Hunter v1.1 | T(n) = T(n-1) + T(n-2) + T(n-3) | tau = 1.839... | TRIBONACCI_RECURRENCE_BEACON |
| Padovan Hunter v1.1 | P(n) = P(n-2) + P(n-3) | rho = 1.325... | PADOVAN_RECURRENCE_BEACON |
| Narayana Hunter v1.1 | N(n) = N(n-1) + N(n-3) | N = 1.466... | NARAYANA_RECURRENCE_BEACON |
| Bounded Hunter v1.0 | Irrational rotation | — | ROTATION_BEACON |
| Reverse Scanner v1.2 | All families, bidirectional | — | *_BEACON / REVERSE_*_BEACON |

Each detector uses a multi-gate pipeline:

- **Gate 1 (Pre-filter):** Cheap ratio/growth test — do consecutive ICI ratios cluster near the family's algebraic constant?
- **Gate 2 (Structural Confirmation):** Permutation significance test (200-500 iterations) against the exact recurrence relationship.
- **Gate 2.5 (Geometric-Backoff Rejection):** Linear regression of |ratio - constant| vs index. True recurrence shows convergence; geometric backoff does not.

## Requirements

```
pip install numpy scipy dpkt
```

`dpkt` is only needed for PCAP input. Zeek conn.log input needs only `numpy` and `scipy`.

## Quick Start

```bash
# Detection gap demo — shows RITA ceiling vs structural detection
python demo.py

# With negative controls
python demo.py --negative

# Run all evidence-hardening tests (~3-4 min)
python run_all_tests.py

# Import a detector directly
python -c "from detectors.beacon_hunter import classify_flow; print(classify_flow.__module__)"
```

## Usage as a library

```python
from detectors.beacon_hunter.detectors import classify_flow

result = classify_flow(timestamps, connection_level=True, min_pkts=7)
print(result["classification"], result["confidence"])
```

## Repository Structure

```
detectors/                  Six detector modules
  beacon_hunter/            Fibonacci / phi-structured beaconing
  tribonacci_hunter/        Tribonacci-constant beaconing
  padovan_hunter/           Plastic-ratio beaconing
  narayana_hunter/          Narayana's-cows beaconing
  bounded_hunter/           Irrational rotation sequences
  reverse_scanner/          Bidirectional wrapper for all families

validation/                 Evidence-hardening test suite
  test1_rita_ceiling.py     RITA component decomposition vs ceiling theorem
  test2_injection.py        5-beacon injection into 200-flow Poisson corpus
  test3_n_sensitivity.py    Detection rate vs connection count (n=6..20)
  test5_gate25_cost.py      Gate 2.5 jitter tolerance measurement
  evidence_suite.py         Full adversarial battery (20+ schedule types)
  backoff_test_battery.py   FP stress test against 8 backoff patterns
  spectral_comparison.py    FFT/Rayleigh periodogram comparison
  validate_ctu13_core.py    CTU-13 dataset validation (forward detectors)
  validate_ctu13_reverse.py CTU-13 dataset validation (reverse scanner)
  investigate_ctu13.py      Deep CTU-13 result analysis
  generate_multiweek_traffic.py  Synthetic 2-week enterprise traffic

tools/                      Ground-truth generation and dataset utilities
  fib_beacon_client.py      Fibonacci-scheduled TCP beacon client
  fib_beacon_server.py      TCP server for beacon validation captures
  inject_fibonacci_beacon.py  Inject Fibonacci flows into Zeek conn.logs
  uwf_to_connlog.py         UWF dataset to Zeek conn.log converter
  download_datasets.sh      Dataset download helper (CTU-13, MAWI, CIC-IDS2017)

results/                    Captured validation results
  evidence_results.json     Full adversarial battery output
  injection_results.json    Fibonacci injection test results
  beacon_report_*.txt       Reports from real PCAP analysis
  rita_fib_results.txt      RITA v5.1.2 comparison output

paper/                      Research paper and figures
  framework_paper_draft.md  Paper source
  framework_paper_final.docx  Formatted paper
  fig*.png                  Paper figures

demo.py                     Detection gap demonstration
run_all_tests.py            All evidence tests in one run
VALIDATION.md               Ground-truth capture procedure
```

## Validation Results

### Adversarial Schedule Battery (20 schedule types, evidence_suite.py)

| Schedule | Classification | Confidence | Correct? |
|---|---|---|---|
| Fibonacci (exact) | FIBONACCI_BEACON | 94.7% | Yes |
| Fibonacci + 10% jitter | FIBONACCI_BEACON | 86.1% | Yes |
| Fibonacci + 25% jitter | FIBONACCI_BEACON | 68.2% | Yes |
| Geometric r=1.5 | FIBONACCI_BEACON | 42.7% | Known FP |
| Geometric r=2.0 | NON_PHYSICAL | — | Yes |
| Poisson | BACKGROUND | — | Yes |
| Exponential backoff (2x) | BACKGROUND | — | Yes |
| Power law / primes / random | BACKGROUND | — | Yes |

### Jitter Tolerance (100 trials per level)

| Jitter | Detection Rate | Avg Confidence |
|---|---|---|
| 0% | 100% | 94.3% |
| 10% | 100% | 81.0% |
| 20% | 100% | 65.9% |
| 25% | 97% | 57.9% |
| 30% | 72% | 49.9% |
| 40% | 9% | — |

### RITA Comparison (live RITA v5.1.2)

A 20-connection Fibonacci beacon injected into a 24-hour Zeek conn.log:
- **RITA score: 45.9%** (Severity: None, below 70% alert threshold)
- **Beacon Hunter: 86.1%** (ADDITIVE_RECURRENCE_BEACON)

### CTU-13 Dataset (101,472 background flows, 13 scenarios)

18 structural activations across 520,040 classifications (0.0035% FPR). Zero structural flags on 2,536 labeled botnet flows. Per-detector: Padovan 7, Narayana 7, Bounded 3, Fibonacci 1, Tribonacci 0.

Run `validation/validate_ctu13_core.py` after downloading CTU-13 binetflow files with `tools/download_datasets.sh`.

## Known Limitations

- **Phi-adjacent geometric sequences (r in [1.50, 1.74]) may pass Gate 1.** Gate 2.5 (convergence check) rejects pure geometric backoff; residual risk is sequences that happen to show convergence-like noise.
- **Bounded Hunter jitter tolerance is ~1-2%.** Distributional signals degrade faster than relational ones.
- **Bootstrap null is ordering-based.** Tests whether ICI ordering matters, not against all possible alternatives.
- **No real malware validation.** All positives are synthetic or lab-generated. The detector is validated against ground-truth captures, not captured malware using phi-scheduling.

## License

AGPL-3.0. Commercial licensing available through RepoSignal.io LLC.
