"""
evidence_suite.py
-----------------
Comprehensive empirical testing for Beacon Hunter paper evidence.

Produces four result sets:
  1. Adversarial schedule battery     -- gate outcomes for 15+ schedule types
  2. Jitter tolerance sweep           -- Fibonacci detection vs jitter level
  3. Sequence length sensitivity      -- detection confidence vs connection count
  4. Null distribution characterization -- recurrence residuals across schedule families

All results are printed as structured text and also saved to JSON.
"""

import sys
import os
import json
import math
import time
import numpy as np
from scipy import stats
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
from detectors.beacon_hunter import detectors

RNG = np.random.default_rng(42)

PHI = detectors.PHI  # 1.6180339887...

# ---------------------------------------------------------------------------
# Schedule generators
# Each returns a sorted array of connection timestamps (seconds from t=0)
# n = number of connections, base = base interval in seconds
# ---------------------------------------------------------------------------

def sched_fibonacci(n=15, base=5.0, jitter_pct=0.0, rng=RNG):
    """Pure Fibonacci: intervals are F[1]*base, F[2]*base, ..."""
    fibs = [1, 1]
    while len(fibs) < n:
        fibs.append(fibs[-1] + fibs[-2])
    intervals = np.array(fibs[:n], dtype=float) * base
    if jitter_pct > 0:
        noise = rng.uniform(-jitter_pct, jitter_pct, size=len(intervals))
        intervals = intervals * (1.0 + noise)
        intervals = np.maximum(intervals, 0.01)
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]  # n+1 timestamps -> n intervals

def sched_geometric(n=15, base=5.0, ratio=2.0, jitter_pct=0.0, rng=RNG):
    """Geometric growth: ICI[k] = base * ratio^k"""
    intervals = base * (ratio ** np.arange(n, dtype=float))
    if jitter_pct > 0:
        noise = rng.uniform(-jitter_pct, jitter_pct, size=n)
        intervals = intervals * (1.0 + noise)
        intervals = np.maximum(intervals, 0.01)
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]

def sched_constant(n=15, interval=30.0, jitter_pct=0.0, rng=RNG):
    """Constant interval (regular beacon)."""
    intervals = np.full(n, interval, dtype=float)
    if jitter_pct > 0:
        noise = rng.uniform(-jitter_pct, jitter_pct, size=n)
        intervals = intervals * (1.0 + noise)
        intervals = np.maximum(intervals, 0.01)
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]

def sched_power_law(n=15, base=5.0, exponent=2.0, rng=RNG):
    """Power-law: ICI[k] = base * (k+1)^exponent"""
    intervals = base * ((np.arange(1, n+1, dtype=float)) ** exponent)
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]

def sched_exponential_backoff(n=15, initial=1.0, multiplier=2.0, cap=300.0, rng=RNG):
    """Exponential backoff with cap (common in application retry logic)."""
    intervals = []
    iv = initial
    for _ in range(n):
        intervals.append(min(iv, cap))
        iv *= multiplier
    intervals = np.array(intervals)
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]

def sched_prime(n=15, base=1.0, rng=RNG):
    """Intervals proportional to successive prime numbers."""
    def primes_up_to(k):
        p = []
        candidate = 2
        while len(p) < k:
            if all(candidate % x != 0 for x in p):
                p.append(candidate)
            candidate += 1
        return p
    intervals = np.array(primes_up_to(n), dtype=float) * base
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]

def sched_poisson(n=15, rate=30.0, rng=RNG):
    """Poisson process: exponentially distributed inter-arrival times."""
    intervals = rng.exponential(scale=rate, size=n)
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]

def sched_random_walk(n=15, base=30.0, step_std=5.0, rng=RNG):
    """Interval follows a random walk (non-negative)."""
    intervals = [base]
    for _ in range(n-1):
        next_iv = intervals[-1] + rng.normal(0, step_std)
        intervals.append(max(next_iv, 1.0))
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]

def sched_logarithmic(n=15, base=5.0, rng=RNG):
    """Logarithmic growth: ICI[k] = base * log(k+2)"""
    intervals = base * np.log(np.arange(2, n+2, dtype=float))
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]

def sched_low_discrepancy(n=15, base=60.0, rng=RNG):
    """Van der Corput-style quasi-random intervals (bounded, structured)."""
    def vdc(k, base=2):
        result = 0.0
        f = 1.0 / base
        i = k
        while i > 0:
            result += f * (i % base)
            i //= base
            f /= base
        return result
    intervals = np.array([vdc(k) * base + base * 0.5 for k in range(1, n+1)])
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]

def sched_triangular_wave(n=15, period=300.0, rng=RNG):
    """Intervals follow a triangular wave pattern (periodic but non-constant)."""
    t = np.linspace(0, 2*np.pi * n / 10, n)
    intervals = 30.0 + 20.0 * np.abs(np.sin(t))
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]

def sched_phi_adjacent(n=15, base=5.0, ratio=1.5, rng=RNG):
    """Geometric with ratio near but not equal to phi (adversarial probe)."""
    return sched_geometric(n=n, base=base, ratio=ratio, rng=rng)

def sched_bounded_multiplicative_jitter(n=15, base=30.0, lo=0.5, hi=2.0, rng=RNG):
    """Each interval is previous * U[lo, hi] -- multiplicative jitter, unbounded growth."""
    intervals = [base]
    for _ in range(n-1):
        intervals.append(intervals[-1] * rng.uniform(lo, hi))
    times = np.concatenate([[0.0], np.cumsum(intervals)])
    return times[:n+1]

# ---------------------------------------------------------------------------
# Core analysis function
# ---------------------------------------------------------------------------

def analyze(conn_times, label):
    """Run full classify_flow pipeline; return structured result dict."""
    result = detectors.classify_flow(
        list(conn_times),
        session_gap=2.0,
        min_pkts=5,
        connection_level=True
    )
    tests = result.get("tests", {})
    ratio_r = tests.get("ratio", {})
    rec_r = tests.get("recurrence", {})
    vg_r = tests.get("variance_growth", {})
    cv_r = tests.get("cv", {})
    ks_r = tests.get("ks", {})

    return {
        "label": label,
        "n_connections": len(conn_times) - 1,
        "classification": result["classification"],
        "confidence": round(result["confidence"], 4),
        "cv": round(cv_r.get("cv") or 0, 4),
        "ks_p": round(ks_r.get("p_val") or 1.0, 4),
        "r_bar": round(ratio_r.get("r_bar") or 0, 4),
        "delta_phi": round(ratio_r.get("delta_phi") or 0, 4),
        "ratio_cv": round(ratio_r.get("ratio_cv") or 0, 4),
        "gate1_label": ratio_r.get("label", "N/A"),
        "gate1_pass": ratio_r.get("label") == "FIBONACCI",
        "rec_mean_err": round(rec_r.get("mean_rel_err") or 0, 4) if rec_r.get("mean_rel_err") is not None else None,
        "rec_p": round(rec_r.get("p_value") or 1.0, 4) if rec_r.get("p_value") is not None else None,
        "gate2_label": rec_r.get("label", "NOT_RUN"),
        "gate2_pass": rec_r.get("label") == "FIBONACCI",
        "vg_label": vg_r.get("label", "N/A"),
    }

# ---------------------------------------------------------------------------
# Test 1: Adversarial schedule battery
# ---------------------------------------------------------------------------

def run_adversarial_battery(n=16, rng=RNG):
    """Run 18 schedule types through the full detector pipeline."""
    print("\n" + "="*70)
    print("TEST 1: ADVERSARIAL SCHEDULE BATTERY")
    print(f"  n={n} connections per schedule, base=5.0s")
    print("="*70)

    schedules = [
        ("Fibonacci (exact)",          sched_fibonacci(n=n, base=5.0, jitter_pct=0.0)),
        ("Fibonacci + 5% jitter",      sched_fibonacci(n=n, base=5.0, jitter_pct=0.05, rng=rng)),
        ("Fibonacci + 10% jitter",     sched_fibonacci(n=n, base=5.0, jitter_pct=0.10, rng=rng)),
        ("Fibonacci + 25% jitter",     sched_fibonacci(n=n, base=5.0, jitter_pct=0.25, rng=rng)),
        ("Geometric r=1.3",            sched_geometric(n=n, base=5.0, ratio=1.3)),
        ("Geometric r=1.5 (phi-adj.)", sched_geometric(n=n, base=5.0, ratio=1.5)),
        ("Geometric r=1.618 (exact phi)", sched_geometric(n=n, base=5.0, ratio=PHI)),
        ("Geometric r=1.7",            sched_geometric(n=n, base=5.0, ratio=1.7)),
        ("Geometric r=2.0",            sched_geometric(n=n, base=5.0, ratio=2.0)),
        ("Geometric r=3.0",            sched_geometric(n=n, base=5.0, ratio=3.0)),
        ("Power law (exp=2)",           sched_power_law(n=n, base=5.0, exponent=2.0)),
        ("Power law (exp=1.5)",         sched_power_law(n=n, base=5.0, exponent=1.5)),
        ("Exponential backoff (x2)",    sched_exponential_backoff(n=n, initial=1.0, multiplier=2.0)),
        ("Exp. backoff + cap (x2)",     sched_exponential_backoff(n=n, initial=1.0, multiplier=2.0, cap=60.0)),
        ("Prime intervals",             sched_prime(n=n, base=1.0)),
        ("Logarithmic growth",          sched_logarithmic(n=n, base=5.0)),
        ("Constant (regular beacon)",   sched_constant(n=n, interval=30.0)),
        ("Constant + 10% jitter",       sched_constant(n=n, interval=30.0, jitter_pct=0.10, rng=rng)),
        ("Poisson (random traffic)",    sched_poisson(n=n, rate=30.0, rng=rng)),
        ("Random walk",                 sched_random_walk(n=n, base=30.0, step_std=5.0, rng=rng)),
        ("Bounded mult. jitter [.5,2]", sched_bounded_multiplicative_jitter(n=n, rng=rng)),
        ("Low-discrepancy (vdC)",       sched_low_discrepancy(n=n, base=60.0)),
        ("Triangular wave",             sched_triangular_wave(n=n)),
    ]

    results = []
    for name, times in schedules:
        r = analyze(times, name)
        results.append(r)

    # Print table
    hdr = f"{'Schedule':<32} {'Class':<20} {'CV':>6} {'r_bar':>6} {'Δφ':>6} {'ratioCV':>7} {'G1':>4} {'RecErr':>7} {'RecP':>6} {'G2':>4} {'Final':<18}"
    print(hdr)
    print("-"*len(hdr))
    for r in results:
        g1 = "PASS" if r["gate1_pass"] else "fail"
        g2 = "PASS" if r["gate2_pass"] else ("----" if r["gate2_label"] == "NOT_RUN" else "fail")
        rec_err = f"{r['rec_mean_err']:.4f}" if r["rec_mean_err"] is not None else "  N/A"
        rec_p   = f"{r['rec_p']:.3f}" if r["rec_p"] is not None else " N/A"
        print(f"{r['label']:<32} {r['classification']:<20} {r['cv']:>6.3f} {r['r_bar']:>6.4f} {r['delta_phi']:>6.4f} {r['ratio_cv']:>7.3f} {g1:>4} {rec_err:>7} {rec_p:>6} {g2:>4} {r['classification']:<18}")

    return results

# ---------------------------------------------------------------------------
# Test 2: Jitter tolerance sweep on Fibonacci
# ---------------------------------------------------------------------------

def run_jitter_sweep(n=15, trials=50, rng=RNG):
    """Test Fibonacci detection across jitter levels 0%-60%, multiple trials."""
    print("\n" + "="*70)
    print("TEST 2: JITTER TOLERANCE SWEEP (Fibonacci schedules)")
    print(f"  n={n} connections, base=5.0s, {trials} trials per jitter level")
    print("="*70)

    jitter_levels = [0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.40, 0.50, 0.60]
    sweep_results = []

    print(f"{'Jitter':>8} {'DetRate':>8} {'AvgConf':>8} {'AvgRecErr':>10} {'AvgRecP':>8} {'AvgRbar':>8}")
    print("-"*56)

    for jitter in jitter_levels:
        det_count = 0
        confs = []
        rec_errs = []
        rec_ps = []
        r_bars = []

        for _ in range(trials):
            times = sched_fibonacci(n=n, base=5.0, jitter_pct=jitter, rng=rng)
            r = analyze(times, "fib")
            if r["classification"] == "FIBONACCI_BEACON":
                det_count += 1
                confs.append(r["confidence"])
            rec_errs.append(r["rec_mean_err"] if r["rec_mean_err"] is not None else 1.0)
            rec_ps.append(r["rec_p"] if r["rec_p"] is not None else 1.0)
            r_bars.append(r["r_bar"])

        det_rate = det_count / trials
        avg_conf = np.mean(confs) if confs else 0.0
        avg_rec_err = np.mean(rec_errs)
        avg_rec_p = np.mean(rec_ps)
        avg_r_bar = np.mean(r_bars)

        sweep_results.append({
            "jitter_pct": jitter,
            "detection_rate": round(det_rate, 3),
            "avg_confidence": round(avg_conf, 3),
            "avg_rec_mean_err": round(avg_rec_err, 4),
            "avg_rec_p": round(avg_rec_p, 4),
            "avg_r_bar": round(avg_r_bar, 4),
            "n_detected": det_count,
            "trials": trials,
        })

        print(f"{jitter*100:>7.0f}% {det_rate:>8.3f} {avg_conf:>8.3f} {avg_rec_err:>10.4f} {avg_rec_p:>8.4f} {avg_r_bar:>8.4f}")

    return sweep_results

# ---------------------------------------------------------------------------
# Test 3: Sequence length sensitivity
# ---------------------------------------------------------------------------

def run_length_sensitivity(jitter=0.10, trials=50, rng=RNG):
    """Test detection rate and confidence vs number of connection events."""
    print("\n" + "="*70)
    print("TEST 3: SEQUENCE LENGTH SENSITIVITY")
    print(f"  Fibonacci + {int(jitter*100)}% jitter, base=5.0s, {trials} trials per length")
    print("="*70)

    lengths = [5, 6, 7, 8, 9, 10, 12, 15, 18, 20, 25]
    len_results = []

    print(f"{'N_conn':>8} {'DetRate':>8} {'AvgConf':>8} {'AvgRecErr':>10} {'G1Rate':>8} {'G2Rate':>8}")
    print("-"*56)

    for n in lengths:
        det_count = 0
        g1_count = 0
        g2_count = 0
        confs = []
        rec_errs = []

        for _ in range(trials):
            times = sched_fibonacci(n=n, base=5.0, jitter_pct=jitter, rng=rng)
            r = analyze(times, "fib")
            if r["classification"] == "FIBONACCI_BEACON":
                det_count += 1
                confs.append(r["confidence"])
            if r["gate1_pass"]:
                g1_count += 1
            if r["gate2_pass"]:
                g2_count += 1
            rec_errs.append(r["rec_mean_err"] if r["rec_mean_err"] is not None else 1.0)

        det_rate = det_count / trials
        g1_rate = g1_count / trials
        g2_rate = g2_count / trials
        avg_conf = np.mean(confs) if confs else 0.0
        avg_rec_err = np.mean(rec_errs)

        len_results.append({
            "n_connections": n,
            "detection_rate": round(det_rate, 3),
            "gate1_rate": round(g1_rate, 3),
            "gate2_rate": round(g2_rate, 3),
            "avg_confidence": round(avg_conf, 3),
            "avg_rec_mean_err": round(avg_rec_err, 4),
            "trials": trials,
        })

        print(f"{n:>8} {det_rate:>8.3f} {avg_conf:>8.3f} {avg_rec_err:>10.4f} {g1_rate:>8.3f} {g2_rate:>8.3f}")

    return len_results

# ---------------------------------------------------------------------------
# Test 4: Null distribution characterization
# ---------------------------------------------------------------------------

def run_null_distribution(n=14, trials=200, rng=RNG):
    """
    Empirically characterize the distribution of recurrence residuals
    for Fibonacci vs five non-Fibonacci schedule families.
    Provides the empirical basis for the permutation null claim.
    """
    print("\n" + "="*70)
    print("TEST 4: NULL DISTRIBUTION CHARACTERIZATION")
    print(f"  n={n} connections, {trials} trials per family")
    print("="*70)

    families = [
        ("Fibonacci (exact)",          lambda: sched_fibonacci(n=n, base=5.0)),
        ("Fibonacci + 10% jitter",     lambda: sched_fibonacci(n=n, base=5.0, jitter_pct=0.10, rng=rng)),
        ("Geometric r=1.5",            lambda: sched_geometric(n=n, base=5.0, ratio=1.5)),
        ("Geometric r=2.0",            lambda: sched_geometric(n=n, base=5.0, ratio=2.0)),
        ("Constant (30s)",             lambda: sched_constant(n=n, interval=30.0)),
        ("Constant + 10% jitter",      lambda: sched_constant(n=n, interval=30.0, jitter_pct=0.10, rng=rng)),
        ("Poisson",                    lambda: sched_poisson(n=n, rate=30.0, rng=rng)),
        ("Power law (exp=2)",          lambda: sched_power_law(n=n, base=5.0, exponent=2.0)),
        ("Prime intervals",            lambda: sched_prime(n=n, base=1.0)),
        ("Random walk",                lambda: sched_random_walk(n=n, rng=rng)),
    ]

    null_results = []
    print(f"{'Family':<32} {'MeanRecErr':>10} {'StdRecErr':>10} {'P(G2pass)':>10} {'Min':>8} {'Max':>8}")
    print("-"*78)

    for name, gen in families:
        rec_errs = []
        g2_passes = 0
        for _ in range(trials):
            times = gen()
            # Compute recurrence residual directly
            ct = np.array(sorted(times), dtype=float)
            icis = np.diff(ct)
            valid = icis[icis > 1e-6]
            if len(valid) < 5:
                continue
            predicted = valid[1:-1] + valid[:-2]
            actual = valid[2:]
            rel_err = np.abs(actual - predicted) / np.maximum(actual, 1e-10)
            mean_err = float(rel_err.mean())
            rec_errs.append(mean_err)

            # Check full gate 2
            r = analyze(times, name)
            if r["gate2_pass"]:
                g2_passes += 1

        rec_errs = np.array(rec_errs)
        g2_rate = g2_passes / trials

        null_results.append({
            "family": name,
            "mean_rec_err": round(float(rec_errs.mean()), 5),
            "std_rec_err": round(float(rec_errs.std()), 5),
            "min_rec_err": round(float(rec_errs.min()), 5),
            "max_rec_err": round(float(rec_errs.max()), 5),
            "pct_pass_gate2": round(g2_rate, 3),
            "trials": trials,
        })

        print(f"{name:<32} {rec_errs.mean():>10.5f} {rec_errs.std():>10.5f} {g2_rate:>10.3f} {rec_errs.min():>8.5f} {rec_errs.max():>8.5f}")

    return null_results

# ---------------------------------------------------------------------------
# Test 5: Phi-adjacency boundary analysis
# ---------------------------------------------------------------------------

def run_phi_boundary(n=14, trials=30, rng=RNG):
    """
    Sweep geometric ratio from 1.3 to 2.0 and measure gate 1 and gate 2
    pass rates. Identifies the phi-adjacency leakage window precisely.
    """
    print("\n" + "="*70)
    print("TEST 5: PHI-ADJACENCY BOUNDARY SWEEP")
    print(f"  Geometric sequences, n={n}, base=5.0s, {trials} trials per ratio")
    print("="*70)

    ratios = [1.20, 1.30, 1.35, 1.40, 1.45, 1.50, 1.55, 1.60, 1.618,
              1.65, 1.70, 1.75, 1.80, 1.90, 2.00, 2.50, 3.00]

    boundary_results = []
    print(f"{'Ratio':>7} {'DeltaPhi':>9} {'RecErr(theory)':>15} {'G1Rate':>8} {'G2Rate':>8} {'FibFlag':>8}")
    print("-"*62)

    for ratio in ratios:
        # Theoretical recurrence residual for geometric r:
        # ICI[n+2] = r^2 * ICI[n], ICI[n+1] + ICI[n] = (r+1) * ICI[n]
        # rel_err = |r^2 - (r+1)| / r^2 = |r^2 - r - 1| / r^2
        theory_rec_err = abs(ratio**2 - ratio - 1) / (ratio**2)

        g1_count = 0
        g2_count = 0
        fib_flag_count = 0

        for _ in range(trials):
            times = sched_geometric(n=n, base=5.0, ratio=ratio)
            r = analyze(times, f"geo_{ratio}")
            if r["gate1_pass"]:
                g1_count += 1
            if r["gate2_pass"]:
                g2_count += 1
            if r["classification"] == "FIBONACCI_BEACON":
                fib_flag_count += 1

        g1_rate = g1_count / trials
        g2_rate = g2_count / trials
        fib_rate = fib_flag_count / trials
        delta_phi = abs(ratio - PHI)

        boundary_results.append({
            "ratio": ratio,
            "delta_phi": round(delta_phi, 5),
            "theory_rec_err": round(theory_rec_err, 5),
            "gate1_rate": round(g1_rate, 3),
            "gate2_rate": round(g2_rate, 3),
            "fib_classification_rate": round(fib_rate, 3),
            "trials": trials,
        })

        print(f"{ratio:>7.3f} {delta_phi:>9.5f} {theory_rec_err:>15.5f} {g1_rate:>8.3f} {g2_rate:>8.3f} {fib_rate:>8.3f}")

    return boundary_results

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("BEACON HUNTER EVIDENCE SUITE")
    print(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"PHI = {PHI:.10f}")

    all_results = {}

    t0 = time.time()

    all_results["adversarial_battery"] = run_adversarial_battery(n=16)
    print(f"\n  [done in {time.time()-t0:.1f}s]")

    t1 = time.time()
    all_results["jitter_sweep"] = run_jitter_sweep(n=15, trials=100)
    print(f"\n  [done in {time.time()-t1:.1f}s]")

    t2 = time.time()
    all_results["length_sensitivity"] = run_length_sensitivity(jitter=0.10, trials=100)
    print(f"\n  [done in {time.time()-t2:.1f}s]")

    t3 = time.time()
    all_results["null_distribution"] = run_null_distribution(n=14, trials=200)
    print(f"\n  [done in {time.time()-t3:.1f}s]")

    t4 = time.time()
    all_results["phi_boundary"] = run_phi_boundary(n=14, trials=50)
    print(f"\n  [done in {time.time()-t4:.1f}s]")

    print(f"\nTotal runtime: {time.time()-t0:.1f}s")

    # Save to JSON
    out = os.path.join(REPO_ROOT, "evidence_results.json")
    with open(out, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to: {out}")
