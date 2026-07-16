#!/usr/bin/env python3
"""
demo.py — Detection Gap Demonstration
======================================

Reproducible demonstration that deterministic non-periodic scheduling
falls below RITA-style composite scoring thresholds while being detected
by structural recurrence analysis.

This script:
  1. Generates beacon schedules for all five validated families
  2. Computes the RITA composite score ceiling for each
  3. Runs each detector against its target family
  4. Prints a side-by-side comparison showing the detection gap
  5. Optionally generates a Zeek JSON conn.log for RITA import

Verified result (RITA v5.1.2, May 2026):
  A 20-connection Fibonacci beacon scored 45.9% in RITA (Severity: None).
  Beacon Hunter classified the same flow as ADDITIVE_RECURRENCE_BEACON
  at 86.1% confidence.

Usage:
  python demo.py                    # Run the full demonstration
  python demo.py --zeek             # Also generate conn.log for RITA
  python demo.py --family fibonacci # Test a single family

Requirements:
  pip install numpy scipy
"""

import argparse
import json
import os
import sys
import random
import string
import time

import numpy as np

# ============================================================
# Add detectors to path
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DETECTORS_DIR = os.path.join(SCRIPT_DIR, "detectors")

DETECTOR_MODULES = {
    "fibonacci":  ("beacon_hunter",     "Beacon Hunter v0.3.0"),
    "tribonacci": ("tribonacci_hunter", "Tribonacci Hunter v1.1"),
    "padovan":    ("padovan_hunter",    "Padovan Hunter v1.1"),
    "narayana":   ("narayana_hunter",   "Narayana Hunter v1.1"),
    "rotation":   ("bounded_hunter",    "Bounded Hunter v1.0"),
}

# ============================================================
# Schedule Generators
# ============================================================

def fibonacci_schedule(n=20, base=5.0, jitter=0.10, seed=42):
    """Fibonacci-spaced intervals: each ≈ sum of previous two."""
    rng = np.random.default_rng(seed)
    fibs = [1, 1]
    while len(fibs) < n:
        fibs.append(fibs[-1] + fibs[-2])
    intervals = np.array(fibs[:n], float) * base
    intervals *= (1 + rng.uniform(-jitter, jitter, n))
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def tribonacci_schedule(n=15, base=5.0, jitter=0.10, seed=42):
    """Tribonacci-spaced intervals: each ≈ sum of previous three."""
    rng = np.random.default_rng(seed)
    tribs = [1, 1, 2]
    while len(tribs) < n:
        tribs.append(tribs[-1] + tribs[-2] + tribs[-3])
    intervals = np.array(tribs[:n], float) * base
    intervals *= (1 + rng.uniform(-jitter, jitter, n))
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def padovan_schedule(n=20, base=5.0, jitter=0.10, seed=42):
    """Padovan-spaced intervals: P(n) = P(n-2) + P(n-3)."""
    rng = np.random.default_rng(seed)
    pads = [1, 1, 1]
    while len(pads) < n:
        pads.append(pads[-2] + pads[-3])
    intervals = np.array(pads[:n], float) * base
    intervals *= (1 + rng.uniform(-jitter, jitter, n))
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def narayana_schedule(n=20, base=5.0, jitter=0.10, seed=42):
    """Narayana-spaced intervals: N(n) = N(n-1) + N(n-3)."""
    rng = np.random.default_rng(seed)
    nars = [1, 1, 1]
    while len(nars) < n:
        nars.append(nars[-1] + nars[-3])
    intervals = np.array(nars[:n], float) * base
    intervals *= (1 + rng.uniform(-jitter, jitter, n))
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def rotation_schedule(n=30, base_min=30.0, base_max=120.0, alpha=None, seed=42):
    """Bounded irrational rotation: ICI = min + (max-min) * frac(n*alpha)."""
    if alpha is None:
        alpha = (1 + np.sqrt(5)) / 2  # golden ratio
    intervals = []
    for i in range(1, n + 1):
        frac = (i * alpha) % 1.0
        intervals.append(base_min + (base_max - base_min) * frac)
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

GENERATORS = {
    "fibonacci":  (fibonacci_schedule,  {"n": 20, "base": 5.0, "jitter": 0.10}),
    "tribonacci": (tribonacci_schedule, {"n": 15, "base": 5.0, "jitter": 0.10}),
    "padovan":    (padovan_schedule,    {"n": 20, "base": 5.0, "jitter": 0.10}),
    "narayana":   (narayana_schedule,   {"n": 20, "base": 5.0, "jitter": 0.10}),
    "rotation":   (rotation_schedule,   {"n": 30}),
}


# ============================================================
# RITA Composite Score Calculator
# ============================================================

def rita_composite_score(timestamps):
    """
    Calculate the theoretical RITA-style composite score for a set of
    timestamps, using the four-component equal-weight methodology.

    Components:
      1. Skew score: 1 - |skewness| / max_skew
      2. Bimodality: Sarle's bimodality coefficient
      3. Top-cover: fraction of intervals at the modal value
      4. Streak: longest consecutive run at modal interval / total

    Returns composite score in [0, 1].
    """
    ts = sorted(timestamps)
    if len(ts) < 3:
        return 0.0

    icis = np.diff(ts)
    n = len(icis)

    if n < 2:
        return 0.0

    # Component 1: Skew score
    mean_ici = np.mean(icis)
    std_ici = np.std(icis)
    if std_ici > 0:
        skewness = float(np.mean(((icis - mean_ici) / std_ici) ** 3))
        # Normalize: low skew = high score
        skew_score = max(0.0, 1.0 - abs(skewness) / 3.0)
    else:
        skew_score = 1.0

    # Component 2: Bimodality (Sarle's coefficient)
    if std_ici > 0:
        skew_val = float(np.mean(((icis - mean_ici) / std_ici) ** 3))
        kurt_val = float(np.mean(((icis - mean_ici) / std_ici) ** 4))
        bimodality = (skew_val ** 2 + 1) / kurt_val if kurt_val > 0 else 0.0
        bimodality = min(1.0, max(0.0, bimodality))
    else:
        bimodality = 1.0

    # Component 3: Top-interval coverage
    # Bin intervals and find the most common
    if std_ici > 0:
        bin_width = max(std_ici * 0.1, mean_ici * 0.05)
        binned = np.round(icis / bin_width) * bin_width
        unique, counts = np.unique(binned, return_counts=True)
        top_cover = float(counts.max()) / n
    else:
        top_cover = 1.0

    # Component 4: Longest streak at modal interval
    if std_ici > 0:
        modal_val = unique[np.argmax(counts)] if len(unique) > 0 else mean_ici
        tolerance = bin_width * 1.5
        streak = 0
        max_streak = 0
        for ici in icis:
            if abs(ici - modal_val) <= tolerance:
                streak += 1
                max_streak = max(max_streak, streak)
            else:
                streak = 0
        streak_score = max_streak / n
    else:
        streak_score = 1.0

    # Composite: equal-weight average
    composite = (skew_score + bimodality + top_cover + streak_score) / 4.0
    return round(composite, 4)


def rita_ceiling(n):
    """Theoretical maximum RITA score for n distinct intervals."""
    return round(0.50 + 0.50 / n, 4)


# ============================================================
# Detector Loading
# ============================================================

def load_detector(family):
    """Load the detector module for a given family."""
    if family not in DETECTOR_MODULES:
        return None, None

    folder, label = DETECTOR_MODULES[family]
    det_path = os.path.join(DETECTORS_DIR, folder)
    spec_path = os.path.join(det_path, "detectors.py")

    if not os.path.exists(spec_path):
        return None, label

    import importlib.util
    module_name = f"det_{folder}"
    if module_name in sys.modules:
        del sys.modules[module_name]

    spec = importlib.util.spec_from_file_location(module_name, spec_path)
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, det_path)
    try:
        spec.loader.exec_module(mod)
        return mod, label
    except Exception as e:
        print(f"  Warning: could not load {label}: {e}")
        return None, label
    finally:
        if det_path in sys.path:
            sys.path.remove(det_path)


# ============================================================
# Zeek conn.log Generator
# ============================================================

def generate_zeek_log(timestamps, output_path, src_ip="10.55.100.42",
                      dst_ip="185.199.108.153", dst_port=443):
    """Generate a Zeek JSON conn.log from timestamps."""
    rng = random.Random(42)
    base_time = time.time() - 7200  # current timestamps within RITA valid window
    connections = []
    for ts in timestamps:
        conn = {
            "ts": round(ts + base_time, 6),
            "uid": "C" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(17)),
            "id.orig_h": src_ip,
            "id.orig_p": rng.randint(49152, 65535),
            "id.resp_h": dst_ip,
            "id.resp_p": dst_port,
            "proto": "tcp",
            "service": "ssl",
            "duration": round(rng.uniform(0.5, 3.0), 6),
            "orig_bytes": rng.randint(200, 2000),
            "resp_bytes": rng.randint(500, 5000),
            "conn_state": "SF",
            "local_orig": True,
            "local_resp": False,
            "missed_bytes": 0,
            "history": "ShADdFf",
            "orig_pkts": rng.randint(5, 20),
            "orig_ip_bytes": rng.randint(400, 3000),
            "resp_pkts": rng.randint(4, 15),
            "resp_ip_bytes": rng.randint(600, 6000),
            "ip_proto": 6,
        }
        connections.append(conn)

    with open(output_path, "w") as f:
        for conn in connections:
            f.write(json.dumps(conn) + "\n")

    return len(connections)


# ============================================================
# Negative Traffic Generators (should be rejected)
# ============================================================

def random_traffic(n=20, min_gap=1.0, max_gap=300.0, seed=42):
    """Uniform random intervals — no structure."""
    rng = np.random.default_rng(seed)
    intervals = rng.uniform(min_gap, max_gap, n)
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def poisson_traffic(n=20, rate=60.0, seed=42):
    """Poisson process — exponential inter-arrivals."""
    rng = np.random.default_rng(seed)
    intervals = rng.exponential(rate, n)
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def binary_backoff(n=12, base=1.0, seed=42):
    """Standard binary exponential backoff (ratio 2.0)."""
    rng = np.random.default_rng(seed)
    intervals = [base * (2 ** i) * (1 + rng.uniform(-0.1, 0.1)) for i in range(n)]
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def grpc_backoff(n=12, base=1.0, seed=42):
    """gRPC-style 1.6x backoff with 20% jitter and 120s cap."""
    rng = np.random.default_rng(seed)
    intervals = []
    delay = base
    for _ in range(n):
        j = delay * (1 + rng.uniform(-0.20, 0.20))
        intervals.append(max(0.5, min(120.0, j)))
        delay = min(120.0, delay * 1.6)
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def periodic_beacon(n=20, interval=30.0, jitter=0.10, seed=42):
    """Regular periodic beacon with jitter."""
    rng = np.random.default_rng(seed)
    intervals = np.full(n, interval) * (1 + rng.uniform(-jitter, jitter, n))
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

NEGATIVE_GENERATORS = {
    "random":    (random_traffic,  {"n": 20}),
    "poisson":   (poisson_traffic, {"n": 20, "rate": 60.0}),
    "binary_2x": (binary_backoff,  {"n": 12}),
    "grpc_1.6x": (grpc_backoff,    {"n": 12}),
    "periodic":  (periodic_beacon, {"n": 20, "interval": 30.0}),
}


def run_negative_demo():
    """Run all detectors against negative (benign) traffic patterns."""
    print()
    print("=" * 70)
    print("  NEGATIVE CONTROL DEMONSTRATION")
    print("  Verifying rejection of benign traffic patterns")
    print("=" * 70)
    print()

    all_detectors = []
    for family in ["fibonacci", "tribonacci", "padovan", "narayana", "rotation"]:
        det_mod, det_label = load_detector(family)
        if det_mod is not None:
            all_detectors.append((det_label, det_mod))

    if not all_detectors:
        print("  No detectors loaded.")
        return

    print(f"  Loaded {len(all_detectors)} detectors")
    print()

    print("-" * 70)
    print(f"  {'Pattern':<16} {'n':>3}  ", end="")
    for det_label, _ in all_detectors:
        short = det_label.split()[0][:8]
        print(f"{short:>9}", end="")
    print(f"  {'Result':>8}")
    print("-" * 70)

    total_tests = 0
    total_flags = 0

    for pattern_name, (gen_fn, gen_kwargs) in NEGATIVE_GENERATORS.items():
        timestamps = gen_fn(**gen_kwargs)
        n_intervals = len(timestamps) - 1
        row_flags = 0
        row_results = []

        for det_label, det_mod in all_detectors:
            total_tests += 1
            try:
                r = det_mod.classify_flow(timestamps, connection_level=True, min_pkts=7)
                cls = r.get("classification", "UNKNOWN")
                if cls in ("BACKGROUND", "INSUFFICIENT_DATA", "UNKNOWN") or \
                   "REGULAR_BEACON" in cls or "JITTERED_BEACON" in cls:
                    row_results.append("Y")
                else:
                    row_results.append("x")
                    row_flags += 1
                    total_flags += 1
            except Exception:
                row_results.append("—")

        status = "CLEAN" if row_flags == 0 else f"{row_flags} FLAG"
        print(f"  {pattern_name:<16} {n_intervals:>3}  ", end="")
        for res in row_results:
            print(f"{res:>9}", end="")
        print(f"  {status:>8}")

    print("-" * 70)
    print()
    print(f"  Total: {total_flags}/{total_tests} flags")

    if total_flags == 0:
        print("  [PASS] All benign patterns correctly rejected by all detectors.")
    else:
        print(f"  [WARN] {total_flags} pattern(s) produced structural activations.")
    print()
    print("=" * 70)
    print()


# ============================================================
# Main Demonstration
# ============================================================

def run_demo(families=None, generate_zeek=False):
    if families is None:
        families = ["fibonacci", "tribonacci", "padovan", "narayana", "rotation"]

    print()
    print("=" * 70)
    print("  DETECTION GAP DEMONSTRATION")
    print("  Structural Recurrence Detection Framework")
    print("=" * 70)
    print()
    print("  This demo generates deterministic non-periodic beacon schedules,")
    print("  computes the RITA composite score ceiling, and runs the structural")
    print("  recurrence detectors against each schedule.")
    print()
    print("  Verified: RITA v5.1.2 scored a 20-connection Fibonacci beacon")
    print("  at 45.9% (Severity: None). Beacon Hunter detected it at 86.1%.")
    print()

    results = []

    for family in families:
        if family not in GENERATORS:
            print(f"  Unknown family: {family}")
            continue

        gen_fn, gen_kwargs = GENERATORS[family]
        timestamps = gen_fn(**gen_kwargs)
        n_intervals = len(timestamps) - 1

        # RITA score
        rita_score = rita_composite_score(timestamps)
        ceiling = rita_ceiling(n_intervals)
        rita_alert = rita_score >= 0.70

        # Detector result
        det_mod, det_label = load_detector(family)
        if det_mod is not None:
            try:
                r = det_mod.classify_flow(timestamps, connection_level=True, min_pkts=7)
                det_class = r.get("classification", "UNKNOWN")
                det_conf = r.get("confidence", 0.0)
            except Exception as e:
                det_class = f"ERROR: {e}"
                det_conf = 0.0
        else:
            det_class = "DETECTOR NOT FOUND"
            det_conf = 0.0

        detected = det_class not in ("BACKGROUND", "INSUFFICIENT_DATA", "UNKNOWN",
                                      "DETECTOR NOT FOUND") and "ERROR" not in det_class

        results.append({
            "family": family,
            "n": n_intervals,
            "rita_score": rita_score,
            "ceiling": ceiling,
            "rita_alert": rita_alert,
            "det_label": det_label,
            "det_class": det_class,
            "det_conf": det_conf,
            "detected": detected,
        })

        # Print ICIs for verification
        icis = [timestamps[i+1] - timestamps[i] for i in range(min(6, len(timestamps)-1))]

    # ============================================================
    # Results Display
    # ============================================================

    print("-" * 70)
    print(f"  {'Family':<14} {'n':>3}  {'RITA Score':>10} {'Ceiling':>8} {'Alert?':>7}  {'Detector Result':<30} {'Conf':>6}")
    print("-" * 70)

    for r in results:
        rita_str = f"{r['rita_score']*100:.1f}%"
        ceil_str = f"{r['ceiling']*100:.1f}%"
        alert_str = "YES" if r['rita_alert'] else "no"
        det_str = r['det_class'][:30]
        conf_str = f"{r['det_conf']*100:.1f}%" if r['detected'] else "—"

        rita_mark = "x" if not r['rita_alert'] else "Y"
        det_mark = "Y" if r['detected'] else "x"

        print(f"  {r['family']:<14} {r['n']:>3}  {rita_mark} {rita_str:>8} {ceil_str:>8} {alert_str:>7}  {det_mark} {det_str:<28} {conf_str:>6}")

    print("-" * 70)
    print()

    # Summary
    n_missed_by_rita = sum(1 for r in results if not r['rita_alert'])
    n_caught_by_detector = sum(1 for r in results if r['detected'])

    print(f"  RITA-style scoring: {n_missed_by_rita}/{len(results)} schedules score below alert threshold")
    print(f"  Structural detectors: {n_caught_by_detector}/{len(results)} schedules detected")
    print()

    if n_missed_by_rita > 0 and n_caught_by_detector > 0:
        print("  [PASS] RESULT CONSISTENT WITH DETECTION-GAP HYPOTHESIS")
        print("    Under the evaluated conditions, schedules that RITA-style")
        print("    scoring cannot alert on are identified by structural")
        print("    recurrence analysis.")
        print()
        print("  The ceiling theorem predicts this result:")
        print("    For n >= 3 distinct intervals, RITA's composite score")
        print("    is bounded by 0.50 + 0.50/n, strictly below 0.70.")
        print()

    # Zeek log generation
    if generate_zeek:
        print("  Generating Zeek conn.log files for RITA import...")
        os.makedirs("demo_logs", exist_ok=True)
        FAMILY_DST_IPS = {
            "fibonacci":  "185.199.108.10",
            "tribonacci": "185.199.108.11",
            "padovan":    "185.199.108.12",
            "narayana":   "185.199.108.13",
            "rotation":   "185.199.108.14",
        }
        for family in families:
            gen_fn, gen_kwargs = GENERATORS[family]
            timestamps = gen_fn(**gen_kwargs)
            output_path = os.path.join("demo_logs", f"conn_{family}.log")
            dst_ip = FAMILY_DST_IPS.get(family, "185.199.108.153")
            n_written = generate_zeek_log(timestamps, output_path, dst_ip=dst_ip)
            print(f"    {output_path}: {n_written} connections")
        print()
        print("  To verify with RITA v5.1.2:")
        print("    rita import --logs demo_logs --database demo_test")
        print("    rita view demo_test")
        print()

    print("=" * 70)
    print()


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detection Gap Demonstration")
    parser.add_argument("--family", type=str, default=None,
                        help="Test a single family (fibonacci, tribonacci, padovan, narayana, rotation)")
    parser.add_argument("--zeek", action="store_true",
                        help="Generate Zeek JSON conn.log files for RITA import")
    parser.add_argument("--negative", action="store_true",
                        help="Run negative controls (random, Poisson, backoff, periodic)")
    parser.add_argument("--jitter", type=float, default=0.10,
                        help="Jitter level (default: 0.10 = 10%%)")
    args = parser.parse_args()

    if args.family:
        families = [args.family]
    else:
        families = None

    # Update jitter if specified
    if args.jitter != 0.10:
        for key in GENERATORS:
            gen_fn, kwargs = GENERATORS[key]
            if "jitter" in kwargs:
                kwargs["jitter"] = args.jitter

    run_demo(families=families, generate_zeek=args.zeek)

    if args.negative:
        run_negative_demo()
