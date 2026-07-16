#!/usr/bin/env python3
"""
test2_injection.py
------------------
Injects one beacon per family into a synthetic background corpus
(200 Poisson flows), then evaluates every flow with both RITA-style
scoring and the structural detector battery.

Shows the detection gap in a mixed-corpus setting: RITA misses all
five injected beacons; structural detectors catch all five; neither
produces false positives on background traffic.

Usage:
    cd recurrence-detection-framework
    python test2_injection.py

Requires: detectors/ directory in the current path (standard repo layout).
"""

import sys
import os
import importlib
import numpy as np

# Add repo root to path so detector imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ---------------------------------------------------------------------------
# Load detectors
# ---------------------------------------------------------------------------

def load_detector(folder):
    """Load a detector module by folder name under detectors/."""
    mod = importlib.import_module(f"detectors.{folder}.detectors")
    return mod

bh  = load_detector("beacon_hunter")
th  = load_detector("tribonacci_hunter")
ph  = load_detector("padovan_hunter")
nh  = load_detector("narayana_hunter")
bnd = load_detector("bounded_hunter")

DETECTORS = [
    ("Beacon Hunter",     bh,  "ADDITIVE_RECURRENCE_BEACON"),
    ("Tribonacci Hunter", th,  "TRIBONACCI_RECURRENCE_BEACON"),
    ("Padovan Hunter",    ph,  "PADOVAN_RECURRENCE_BEACON"),
    ("Narayana Hunter",   nh,  "NARAYANA_RECURRENCE_BEACON"),
    ("Bounded Hunter",    bnd, "ROTATION_BEACON"),
]

# ---------------------------------------------------------------------------
# RITA-style scorer (same formula as paper Section 4.1)
# ---------------------------------------------------------------------------

def sarles_bimodality(x):
    n = len(x)
    if n < 4:
        return 0.5
    m = np.mean(x)
    s = np.std(x, ddof=1)
    if s == 0:
        return 0.0
    skew = np.mean(((x - m) / s) ** 3)
    kurt = np.mean(((x - m) / s) ** 4) - 3
    denom = kurt + 3 * (n - 1) ** 2 / ((n - 2) * (n - 3)) if n > 3 else 1.0
    if abs(denom) < 1e-10:
        return 0.5
    return float(min(1.0, max(0.0, (skew ** 2 + 1) / denom)))


def rita_score(timestamps):
    """Compute RITA-style composite score for a list of timestamps."""
    ts = np.array(sorted(timestamps), dtype=float)
    icis = np.diff(ts)
    if len(icis) < 3:
        return 0.0
    n = len(icis)
    m = np.mean(icis)
    s = np.std(icis, ddof=1) if n > 1 else 0.0
    raw_skew = float(np.mean(((icis - m) / (s + 1e-10)) ** 3)) if s > 0 else 0.0
    skew_score = max(0.0, 1.0 - abs(raw_skew) / 3.0)
    bimodal = sarles_bimodality(icis)
    rounded = np.round(icis).astype(int)
    _, counts = np.unique(rounded, return_counts=True)
    top_cover = float(counts.max()) / n
    modal_val = np.unique(rounded)[np.argmax(counts)]
    streak = cur = 0
    for v in rounded:
        if v == modal_val:
            cur += 1
            streak = max(streak, cur)
        else:
            cur = 0
    return (skew_score + bimodal + top_cover + streak / n) / 4.0


# ---------------------------------------------------------------------------
# Schedule generators (return timestamp lists starting at 0)
# ---------------------------------------------------------------------------

def fibonacci_timestamps(n=20, base=5.0, jitter=0.10, seed=42):
    rng = np.random.default_rng(seed)
    a, b = 1, 1
    ivs = []
    for _ in range(n):
        ivs.append(a * base)
        a, b = b, a + b
    ivs = np.array(ivs) * (1 + rng.uniform(-jitter, jitter, n))
    return list(np.concatenate([[0.0], np.cumsum(ivs)]))


def tribonacci_timestamps(n=15, base=5.0, jitter=0.10, seed=42):
    rng = np.random.default_rng(seed)
    seq = [1, 1, 2]
    while len(seq) < n:
        seq.append(seq[-1] + seq[-2] + seq[-3])
    ivs = np.array(seq[:n], float) * base * (1 + rng.uniform(-jitter, jitter, n))
    return list(np.concatenate([[0.0], np.cumsum(ivs)]))


def padovan_timestamps(n=20, base=5.0, jitter=0.10, seed=42):
    rng = np.random.default_rng(seed)
    seq = [1, 1, 1]
    while len(seq) < n:
        seq.append(seq[-2] + seq[-3])
    ivs = np.array(seq[:n], float) * base * (1 + rng.uniform(-jitter, jitter, n))
    return list(np.concatenate([[0.0], np.cumsum(ivs)]))


def narayana_timestamps(n=20, base=5.0, jitter=0.10, seed=42):
    rng = np.random.default_rng(seed)
    seq = [1, 1, 1]
    while len(seq) < n:
        seq.append(seq[-1] + seq[-3])
    ivs = np.array(seq[:n], float) * base * (1 + rng.uniform(-jitter, jitter, n))
    return list(np.concatenate([[0.0], np.cumsum(ivs)]))


def rotation_timestamps(n=30, lo=30.0, hi=120.0, seed=42):
    alpha = (1 + np.sqrt(5)) / 2.0
    ivs = [lo + (hi - lo) * ((i * alpha) % 1.0) for i in range(1, n + 1)]
    return list(np.concatenate([[0.0], np.cumsum(ivs)]))


def poisson_timestamps(n=20, mean_interval=60.0, seed=0):
    rng = np.random.default_rng(seed)
    ivs = rng.exponential(mean_interval, n)
    return list(np.concatenate([[0.0], np.cumsum(ivs)]))


# ---------------------------------------------------------------------------
# Build corpus
# ---------------------------------------------------------------------------

ALERT_THRESHOLD = 0.70
N_BACKGROUND = 200

BEACON_SPECS = [
    ("fibonacci_beacon",  bh,  "ADDITIVE_RECURRENCE_BEACON",  20, 0.525, fibonacci_timestamps(n=20,  seed=1)),
    ("tribonacci_beacon", th,  "TRIBONACCI_RECURRENCE_BEACON", 15, 0.533, tribonacci_timestamps(n=15, seed=1)),
    ("padovan_beacon",    ph,  "PADOVAN_RECURRENCE_BEACON",    20, 0.525, padovan_timestamps(n=20,    seed=1)),
    ("narayana_beacon",   nh,  "NARAYANA_RECURRENCE_BEACON",   20, 0.525, narayana_timestamps(n=20,   seed=1)),
    ("rotation_beacon",   bnd, "ROTATION_BEACON",               30, 0.517, rotation_timestamps(n=30,  seed=1)),
]

# Background: Poisson flows at realistic enterprise mean intervals
rng_bg = np.random.default_rng(0)
BACKGROUND = []
for i in range(N_BACKGROUND):
    mean_iv = float(rng_bg.choice([15, 30, 60, 120, 300]))
    n_conns = int(rng_bg.integers(8, 30))
    ts = poisson_timestamps(n=n_conns, mean_interval=mean_iv, seed=i + 1000)
    BACKGROUND.append((f"bg_{i:03d}", ts))


# ---------------------------------------------------------------------------
# Evaluate
# ---------------------------------------------------------------------------

def classify_all_detectors(timestamps):
    """Run all five structural detectors. Return (any_fired, results_dict)."""
    any_fired = False
    results = {}
    for name, mod, target in DETECTORS:
        try:
            r = mod.classify_flow(timestamps, connection_level=True, min_pkts=7)
            fired = r["classification"] == target
            results[name] = {"fired": fired, "confidence": round(r.get("confidence", 0.0), 3)}
            if fired:
                any_fired = True
        except Exception as exc:
            results[name] = {"fired": False, "confidence": 0.0, "error": str(exc)}
    return any_fired, results


def main():
    print()
    print("TEST 2: ADVERSARIAL INJECTION — Detection Gap in Mixed Corpus")
    print("=" * 70)
    print(f"Corpus: {len(BEACON_SPECS)} injected beacons + {N_BACKGROUND} Poisson background flows")
    print(f"RITA alert threshold: {ALERT_THRESHOLD}")
    print()

    # --- Beacon evaluation ---
    print("INJECTED BEACONS:")
    print(f"{'Flow':<22} {'RITA':>6} {'Ceiling':>8} {'RITA_alert':>11} {'Detected':>9} {'Conf':>6}")
    print("-" * 70)

    beacon_rita_alerts = 0
    beacon_detected = 0

    for flow_id, mod, target, n, ceiling, ts in BEACON_SPECS:
        rita = rita_score(ts)
        r = mod.classify_flow(ts, connection_level=True, min_pkts=7)
        detected = r["classification"] == target
        conf = r.get("confidence", 0.0)
        rita_alerted = rita >= ALERT_THRESHOLD

        if rita_alerted:
            beacon_rita_alerts += 1
        if detected:
            beacon_detected += 1

        rita_str  = "YES ⚠" if rita_alerted else "no"
        det_str   = "YES ✓" if detected     else "MISSED"
        print(
            f"{flow_id:<22} {rita:>6.3f} {ceiling:>8.3f} {rita_str:>11} "
            f"{det_str:>9} {conf:>6.3f}"
        )

    # --- Background evaluation ---
    print()
    print("BACKGROUND FLOWS (Poisson, 200 flows):")

    bg_rita_alerts   = 0
    bg_struct_fires  = 0

    for flow_id, ts in BACKGROUND:
        rita = rita_score(ts)
        if rita >= ALERT_THRESHOLD:
            bg_rita_alerts += 1
        any_fired, _ = classify_all_detectors(ts)
        if any_fired:
            bg_struct_fires += 1

    print(f"  RITA alerts (>= {ALERT_THRESHOLD}):     {bg_rita_alerts} / {N_BACKGROUND}")
    print(f"  Structural activations:  {bg_struct_fires} / {N_BACKGROUND}")

    # --- Summary ---
    print()
    print("DETECTION GAP SUMMARY:")
    print(f"  {'Metric':<40} {'Result'}")
    print(f"  {'-'*55}")
    print(f"  {'Beacons caught by structural detectors':<40} {beacon_detected}/{len(BEACON_SPECS)}")
    print(f"  {'Beacons caught by RITA':<40} {beacon_rita_alerts}/{len(BEACON_SPECS)}")
    print(f"  {'Background structural FP':<40} {bg_struct_fires}/{N_BACKGROUND}  ({100*bg_struct_fires/N_BACKGROUND:.1f}%)")
    print(f"  {'Background RITA FP':<40} {bg_rita_alerts}/{N_BACKGROUND}  ({100*bg_rita_alerts/N_BACKGROUND:.1f}%)")

    print()
    if beacon_detected == len(BEACON_SPECS) and beacon_rita_alerts == 0:
        print("RESULT: DETECTION GAP CONFIRMED.")
        print("  Structural detectors caught all beacons. RITA caught none.")
    else:
        print("RESULT: PARTIAL — check individual rows above.")


if __name__ == "__main__":
    main()
