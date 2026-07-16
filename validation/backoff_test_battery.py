#!/usr/bin/env python3
"""
backoff_test_battery.py (v2 -- fixed)
-------------------------------------
Tests all detectors against realistic exponential backoff and retry patterns.

FIXES from v1:
  1. Exceptions are now logged as ERRORS, not silently hidden as "no flag."
     A detector crash on backoff input is a bug, not a clean pass.
  2. Each detector is loaded with a unique module name to prevent
     sys.modules cross-contamination between detectors sharing helper names.
  3. Results now track three categories: flags, clean passes, and errors.
  4. Frame output honestly as "synthetic stress test" not "real-world FPR."

USAGE:
  python backoff_test_battery.py
"""

import numpy as np
import sys
import os
import importlib
import traceback

# ============================================================
# CONFIGURATION -- repo-relative detector imports
# ============================================================

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

DETECTOR_FOLDERS = [
    ("Beacon Hunter",     "beacon_hunter"),
    ("Tribonacci Hunter", "tribonacci_hunter"),
    ("Padovan Hunter",    "padovan_hunter"),
    ("Narayana Hunter",   "narayana_hunter"),
    ("Reverse Scanner",   "reverse_scanner"),
    ("Bounded Hunter",    "bounded_hunter"),
]

# ============================================================
# BACKOFF PATTERN GENERATORS
# ============================================================

def binary_backoff(n=12, base=1.0, seed=None):
    """Standard binary exponential backoff: base x 2^i"""
    intervals = [base * (2 ** i) for i in range(n)]
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def aws_sdk_backoff(n=12, base=1.0, cap=20.0, seed=42):
    """AWS SDK: base x 2^i with full jitter [0, min(cap, base x 2^i)]"""
    rng = np.random.default_rng(seed)
    intervals = []
    for i in range(n):
        max_delay = min(cap, base * (2 ** i))
        intervals.append(rng.uniform(0.1, max_delay))
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def kubernetes_backoff(n=12, base=10.0, cap=300.0, seed=42):
    """Kubernetes: base x 2^i, capped, with +/-10% jitter"""
    rng = np.random.default_rng(seed)
    intervals = []
    for i in range(n):
        delay = min(cap, base * (2 ** i))
        delay *= (1 + rng.uniform(-0.10, 0.10))
        intervals.append(max(1.0, delay))
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def tcp_retransmit(n=8, seed=None):
    """TCP retransmission: 1, 2, 4, 8, 16, 32, 64, 128..."""
    intervals = [2.0 ** i for i in range(n)]
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def browser_reconnect(n=10, cap=30.0, seed=42):
    """Browser reconnect: 1s base, 2x growth, cap 30s, +/-30% jitter"""
    rng = np.random.default_rng(seed)
    intervals = []
    for i in range(n):
        delay = min(cap, 1.0 * (2 ** i))
        delay *= (1 + rng.uniform(-0.30, 0.30))
        intervals.append(max(0.5, delay))
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def cdn_retry(n=8, base=0.5, seed=42):
    """CDN retry: short intervals with 25% jitter, 2x growth"""
    rng = np.random.default_rng(seed)
    intervals = []
    for i in range(n):
        delay = base * (2 ** i)
        delay *= (1 + rng.uniform(-0.25, 0.25))
        intervals.append(max(0.1, delay))
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def grpc_backoff(n=12, initial=1.0, multiplier=1.6, cap=120.0, seed=42):
    """gRPC: initial x multiplier^i, +/-20% jitter, capped"""
    rng = np.random.default_rng(seed)
    intervals = []
    delay = initial
    for i in range(n):
        jittered = delay * (1 + rng.uniform(-0.20, 0.20))
        intervals.append(max(0.5, min(cap, jittered)))
        delay = min(cap, delay * multiplier)
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))

def mobile_stepped(n=10, seed=42):
    """Mobile app: stepped delays 5, 10, 30, 60, 120, 300s repeating"""
    rng = np.random.default_rng(seed)
    steps = [5.0, 10.0, 30.0, 60.0, 120.0, 300.0]
    intervals = []
    for i in range(n):
        base = steps[min(i, len(steps)-1)]
        intervals.append(base * (1 + rng.uniform(-0.15, 0.15)))
    return list(np.concatenate([[0.0], np.cumsum(intervals)]))


PATTERNS = [
    ("Binary backoff (2x)",       binary_backoff,    {"n": 12}),
    ("AWS SDK (full jitter)",     aws_sdk_backoff,   {"n": 12}),
    ("Kubernetes (cap 300s)",     kubernetes_backoff, {"n": 12}),
    ("TCP retransmit",            tcp_retransmit,    {"n": 8}),
    ("Browser reconnect",         browser_reconnect, {"n": 10}),
    ("CDN retry (short)",         cdn_retry,         {"n": 8}),
    ("gRPC (1.6x multiplier)",   grpc_backoff,      {"n": 12}),
    ("Mobile stepped",            mobile_stepped,    {"n": 10}),
]


# ============================================================
# LOAD DETECTORS (repo-relative imports)
# ============================================================

def load_detector(name, folder):
    """Import detectors module from detectors/<folder>/detectors.py via importlib."""
    module_path = f"detectors.{folder}.detectors"
    try:
        mod = importlib.import_module(module_path)
        return mod
    except Exception as e:
        print(f"  X {name}: import error ({module_path}): {e}")
        traceback.print_exc()
        return None


def classify(detector_mod, timestamps):
    """
    Run classify_flow on timestamps.
    Returns:
      ("flag", description)   -- detector fired (potential FP)
      ("clean", None)         -- detector correctly returned BACKGROUND
      ("error", description)  -- detector threw an exception
    """
    try:
        result = detector_mod.classify_flow(timestamps, connection_level=True)
        cls = result.get("classification", "UNKNOWN")
        fam = result.get("family", "")
        conf = result.get("confidence", 0)
        if cls in ("BACKGROUND", "INSUFFICIENT_DATA", "UNKNOWN"):
            return ("clean", None)
        if cls == "REGULAR_BEACON" or cls == "JITTERED_BEACON":
            return ("clean", None)  # Periodic detection is expected, not structural FP
        return ("flag", f"{fam or cls} ({conf*100:.0f}%)")
    except Exception as e:
        return ("error", str(e))


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 75)
    print("  BACKOFF FALSE-POSITIVE STRESS TEST (v2)")
    print("  Synthetic isolated retry patterns -- not real-world FPR measurement")
    print("=" * 75)
    print()

    # Load detectors
    detectors = []
    for name, folder in DETECTOR_FOLDERS:
        mod = load_detector(name, folder)
        if mod:
            detectors.append((name, mod))
            print(f"  + Loaded {name}")
        else:
            print(f"  X Skipped {name}")
    print()

    if not detectors:
        print("No detectors loaded. Check that detector modules exist under detectors/.")
        sys.exit(1)

    # Results matrix
    n_trials = 50
    results = {}

    for pat_name, gen_fn, kwargs in PATTERNS:
        print(f"Testing: {pat_name} ({n_trials} trials)...")
        results[pat_name] = {}

        for det_name, det_mod in detectors:
            flags = 0
            errors = 0
            flag_details = []
            error_details = []

            for seed in range(n_trials):
                kw = {**kwargs, "seed": seed + 1000}
                try:
                    times = gen_fn(**kw)
                except TypeError:
                    times = gen_fn(**{k: v for k, v in kw.items() if k != "seed"})

                status, detail = classify(det_mod, times)
                if status == "flag":
                    flags += 1
                    if len(flag_details) < 3:
                        flag_details.append(f"    seed={seed}: {detail}")
                elif status == "error":
                    errors += 1
                    if len(error_details) < 2:
                        error_details.append(f"    seed={seed}: ERROR: {detail}")

            results[pat_name][det_name] = (flags, errors, n_trials)

            if flags > 0:
                print(f"  ! {det_name}: {flags}/{n_trials} FLAGS ({flags/n_trials:.0%})")
                for d in flag_details:
                    print(d)
            if errors > 0:
                print(f"  X {det_name}: {errors}/{n_trials} ERRORS (detector crashed)")
                for d in error_details:
                    print(d)
            if flags == 0 and errors == 0:
                print(f"  + {det_name}: 0/{n_trials} (clean)")
        print()

    # Summary table
    print("=" * 75)
    print("  RESULTS SUMMARY")
    print("  (Synthetic stress test -- not operational FPR)")
    print("=" * 75)
    print()

    det_names = [n for n, _ in detectors]
    header = f"{'Pattern':<28}" + "".join(f"{n:<14}" for n in det_names)
    print(header)
    print("-" * len(header))

    total_flags = 0
    total_errors = 0
    for pat_name, _, _ in PATTERNS:
        row = f"{pat_name:<28}"
        for det_name in det_names:
            flags, errors, trials = results[pat_name].get(det_name, (0, 0, n_trials))
            total_flags += flags
            total_errors += errors
            if errors > 0:
                cell = f"E:{errors}"
            elif flags > 0:
                cell = f"!{flags}/{trials}"
            else:
                cell = "0"
            row += f"{cell:<14}"
        print(row)

    print()
    print(f"Total flags: {total_flags}")
    print(f"Total errors: {total_errors}")
    print()

    if total_errors > 0:
        print(f"! {total_errors} detector errors occurred. These are BUGS, not clean passes.")
        print("  Review error details above before interpreting flag counts.")
        print()

    if total_flags == 0 and total_errors == 0:
        print("+ ALL CLEAR: Zero flags, zero errors across all patterns x all detectors.")
    elif total_flags > 0:
        print(f"! {total_flags} flag(s) detected on synthetic retry patterns.")
        print("  These indicate structural overlap between retry backoff and detection gates.")
        print("  Investigate whether Gate 2 recurrence tests can discriminate geometric")
        print("  growth from additive recurrence (convergence-slope test recommended).")
    print()
