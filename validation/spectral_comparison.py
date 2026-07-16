#!/usr/bin/env python3
"""
spectral_comparison.py (v2 -- fixed)
------------------------------------
Tests whether non-periodic structured schedules produce detectable spectral
peaks using point-process periodogram analysis.

FIXES from v1:
  - v1 applied Lomb-Scargle to mean-centered ICIs indexed by connection number.
    A perfect periodic beacon has constant ICIs -> mean-centering gives zeros -> NaN.
    The positive control FAILED, invalidating all results.
  - v2 uses the Rayleigh/Schuster periodogram, which is the correct spectral
    test for point processes (event timestamps). For each candidate period P,
    it computes how well events phase-align: R = |mean(exp(2*pi*i*t/P))|^2.
    Periodic events cluster at a specific phase -> high R.
    Non-periodic events scatter uniformly -> low R.

DEPENDENCIES:
  pip install numpy scipy
"""

import numpy as np
from scipy import stats as sp_stats
import sys

# ============================================================
# CONSTANTS
# ============================================================

PHI = (1 + np.sqrt(5)) / 2
PRIMES = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]

# ============================================================
# SCHEDULE GENERATORS
# ============================================================

def periodic_times(n=50, interval=30.0, jitter=0.0, seed=42):
    rng = np.random.default_rng(seed)
    ivs = np.full(n, interval)
    if jitter > 0:
        ivs *= (1 + rng.uniform(-jitter, jitter, n))
    return np.concatenate([[0.0], np.cumsum(ivs)])

def fibonacci_times(n=30, base=5.0):
    fib = [1, 1]
    while len(fib) < n: fib.append(fib[-1] + fib[-2])
    return np.concatenate([[0.0], np.cumsum(np.array(fib[:n], float) * base)])

def tribonacci_times(n=20, base=5.0):
    seq = [1, 1, 2]
    while len(seq) < n: seq.append(seq[-1] + seq[-2] + seq[-3])
    return np.concatenate([[0.0], np.cumsum(np.array(seq[:n], float) * base)])

def padovan_times(n=30, base=5.0):
    seq = [1, 1, 1]
    while len(seq) < n: seq.append(seq[-2] + seq[-3])
    return np.concatenate([[0.0], np.cumsum(np.array(seq[:n], float) * base)])

def narayana_times(n=30, base=5.0):
    seq = [1, 1, 1]
    while len(seq) < n: seq.append(seq[-1] + seq[-3])
    return np.concatenate([[0.0], np.cumsum(np.array(seq[:n], float) * base)])

def prime_times(n=25, base=5.0):
    return np.concatenate([[0.0], np.cumsum(np.array(PRIMES[:n], float) * base)])

def polynomial_times(n=30, base=2.0, alpha=2.0):
    ivs = base * np.arange(1, n+1, dtype=float) ** alpha
    return np.concatenate([[0.0], np.cumsum(ivs)])

def rotation_times(n=50, lo=30.0, hi=120.0):
    fracs = np.array([(i * PHI) % 1.0 for i in range(1, n+1)])
    ivs = lo + (hi - lo) * fracs
    return np.concatenate([[0.0], np.cumsum(ivs)])

def poisson_times(n=50, rate=60.0, seed=42):
    rng = np.random.default_rng(seed)
    return np.concatenate([[0.0], np.cumsum(rng.exponential(rate, n))])


# ============================================================
# RAYLEIGH / SCHUSTER PERIODOGRAM (correct for point processes)
# ============================================================

def rayleigh_periodogram(timestamps, periods):
    """
    Compute Rayleigh statistic for each candidate period.

    For a set of event times {t_k} and candidate period P:
      R(P) = (2/N) * |sum(exp(2*pi*i * t_k / P))|^2

    R is high when events are phase-aligned with period P.
    Under the null hypothesis (uniform random phases), 2*R ~ chi2(2).

    Parameters
    ----------
    timestamps : array of event times
    periods : array of candidate periods to test

    Returns
    -------
    rayleigh_stats : array of R values for each period
    """
    ts = np.array(timestamps, dtype=float)
    ts = ts - ts[0]  # shift to start at 0
    N = len(ts)

    R = np.zeros(len(periods))
    for j, P in enumerate(periods):
        if P <= 0:
            continue
        phases = (2 * np.pi * ts / P) % (2 * np.pi)
        cos_sum = np.sum(np.cos(phases))
        sin_sum = np.sum(np.sin(phases))
        R[j] = (2.0 / N) * (cos_sum**2 + sin_sum**2)
    return R


def analyze_spectral(timestamps, label=""):
    """
    Point-process spectral analysis using the Rayleigh periodogram.

    Tests a grid of candidate periods from the minimum ICI to the
    total observation span. Reports the peak Rayleigh statistic and
    its significance under the null hypothesis of uniform random phases.
    """
    ts = np.array(timestamps, dtype=float)
    N = len(ts)
    if N < 6:
        return {"label": label, "n": N, "error": "too few points"}

    ts = ts - ts[0]
    T = ts[-1]
    if T <= 0:
        return {"label": label, "n": N, "error": "zero time range"}

    icis = np.diff(ts)
    min_ici = float(icis[icis > 0].min()) if np.any(icis > 0) else 1.0
    max_ici = float(icis.max())

    # Period search range: from min_ICI to a reasonable behavioral maximum
    # Using min_ICI avoids sub-ICI harmonic artifacts.
    # Capping at max_ICI x 5 or T/4 avoids non-stationarity artifacts where
    # the Rayleigh test detects event-density clustering at observation-scale
    # periods rather than true periodicity.
    min_period = min_ici * 0.9
    max_period = min(max_ici * 5, T / 4)
    if max_period <= min_period:
        max_period = T / 2  # fallback for very short/uniform sequences
    n_periods = min(2000, max(200, N * 20))
    periods = np.linspace(max(min_period, 0.5), max_period, n_periods)

    # Compute Rayleigh periodogram
    R = rayleigh_periodogram(ts, periods)

    # Find peak
    peak_idx = np.argmax(R)
    max_R = float(R[peak_idx])
    peak_period = float(periods[peak_idx])
    peak_freq = 1.0 / peak_period if peak_period > 0 else 0

    # Significance: under null (uniform random phases), R ~ Exp(1) for large N
    # P(R > z) = exp(-z) for a single period
    # With M independent trials (periods searched): FAP = 1 - (1 - exp(-z))^M
    # Use the number of periods actually searched, not N/2
    M = n_periods
    single_p = np.exp(-max_R)
    fap = 1.0 - (1.0 - single_p) ** M
    fap = max(0.0, min(1.0, fap))

    return {
        "label": label,
        "n_points": N,
        "max_R": round(max_R, 3),
        "peak_period": round(peak_period, 2),
        "peak_freq": round(peak_freq, 6),
        "fap": fap,
        "significant_001": fap < 0.01,
        "significant_005": fap < 0.05,
        "significant_010": fap < 0.10,
        "mean_R": round(float(np.mean(R)), 3),
        "median_ici": round(float(np.median(icis)), 2),
    }


# ============================================================
# AUTOCORRELATION (fixed: on ICI differences, not raw ICIs)
# ============================================================

def analyze_autocorrelation(timestamps, label=""):
    """
    Test ICI autocorrelation. For periodic beacons, ICIs are constant
    so we test the ICI differences (delta-ICIs) which capture jitter structure.
    For growing schedules, raw ICIs are monotonic so we test delta-ICIs
    to separate trend from periodic structure.
    """
    ts = np.array(timestamps, dtype=float)
    icis = np.diff(ts)
    n = len(icis)
    if n < 8:
        return {"label": label, "n": n, "error": "too few ICIs"}

    # Use delta-ICIs (first differences of ICIs) to remove trend
    delta_icis = np.diff(icis)
    nd = len(delta_icis)
    if nd < 4:
        return {"label": label, "n": n, "error": "too few delta-ICIs"}

    centered = delta_icis - delta_icis.mean()
    var = np.var(centered)
    if var < 1e-15:
        # Constant delta-ICIs (e.g., quadratic growth)
        return {"label": label, "n_ici": n, "max_autocorr": 0.0,
                "max_lag": 0, "threshold_95": 1.96/np.sqrt(nd),
                "significant": False, "note": "constant delta-ICIs"}

    max_lag = min(nd // 2, 15)
    autocorrs = []
    for lag in range(1, max_lag + 1):
        if lag >= nd:
            break
        c = np.corrcoef(centered[:nd-lag], centered[lag:])[0, 1]
        if not np.isnan(c):
            autocorrs.append((lag, float(c)))

    if not autocorrs:
        return {"label": label, "n_ici": n, "max_autocorr": 0, "max_lag": 0}

    threshold = 1.96 / np.sqrt(nd)
    max_ac = max(autocorrs, key=lambda x: abs(x[1]))
    significant = abs(max_ac[1]) > threshold

    return {
        "label": label,
        "n_ici": n,
        "max_autocorr": round(max_ac[1], 4),
        "max_lag": max_ac[0],
        "threshold_95": round(threshold, 4),
        "significant": significant,
    }


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 75)
    print("  SPECTRAL & AUTOCORRELATION ANALYSIS (v2 -- Rayleigh periodogram)")
    print("  Testing whether non-periodic schedules produce detectable signals")
    print("=" * 75)
    print()

    schedules = [
        # Positive controls -- MUST show significant peaks or the test is broken
        ("Periodic 30s (no jitter)",     periodic_times(50, 30.0, 0.0)),
        ("Periodic 30s (10% jitter)",    periodic_times(50, 30.0, 0.10)),
        ("Periodic 30s (25% jitter)",    periodic_times(50, 30.0, 0.25)),

        # Negative control -- should show NO peaks
        ("Poisson random (lambda=60s)",  poisson_times(50, 60.0)),

        # Non-periodic families (the test subjects)
        ("Fibonacci (phi~1.618)",        fibonacci_times(30)),
        ("Tribonacci (tau~1.839)",       tribonacci_times(20)),
        ("Padovan (rho~1.325)",          padovan_times(30)),
        ("Narayana (N~1.466)",           narayana_times(30)),
        ("Primes (PNT)",                 prime_times(25)),
        ("Polynomial (n^2)",             polynomial_times(30)),
        ("Rotation (phi, 30-120s)",      rotation_times(50)),
    ]

    print("-" * 75)
    print(f"{'Schedule':<32} {'Peak R':>8} {'Peak Period':>12} {'FAP':>10} {'Sig?':>6} {'dAC':>8} {'AC?':>5}")
    print("-" * 75)

    periodic_detected = 0
    nonperiodic_missed = 0
    n_periodic = 0
    n_nonperiodic = 0

    for label, times in schedules:
        spec = analyze_spectral(times, label)
        ac = analyze_autocorrelation(times, label)

        if "error" in spec:
            print(f"{label:<32} {'ERROR':>8} {spec['error']}")
            continue

        sig_marker = "YES" if spec["significant_001"] else ("~" if spec["significant_010"] else "no")
        ac_marker = "Y" if ac.get("significant", False) else "n"
        med_ici = spec.get("median_ici", 0)

        print(f"{label:<32} {spec['max_R']:>8.1f} {spec['peak_period']:>10.1f}s {spec['fap']:>10.4f} "
              f"{sig_marker:>6} {ac.get('max_autocorr', 0):>8.3f} {ac_marker:>5}")

        # Track classification
        is_periodic = "Periodic" in label
        if is_periodic:
            n_periodic += 1
            if spec["significant_001"]:
                periodic_detected += 1
        elif "Poisson" not in label:
            n_nonperiodic += 1
            if not spec["significant_010"]:
                nonperiodic_missed += 1

    print("-" * 75)
    print()

    # Validate positive controls first
    print("VALIDATION:")
    print()
    if periodic_detected >= 2:
        print(f"  + Positive control PASSED: {periodic_detected}/{n_periodic} periodic beacons detected (FAP < 0.01)")
        print(f"    The test is correctly calibrated.")
    elif periodic_detected >= 1:
        print(f"  ~ Positive control PARTIAL: {periodic_detected}/{n_periodic} periodic beacons detected")
        print(f"    Some periodic controls missed -- interpret non-periodic results with caution.")
    else:
        print(f"  X Positive control FAILED: {periodic_detected}/{n_periodic} periodic beacons detected")
        print(f"    TEST IS INVALID -- do not use these results.")
        print(f"    The spectral method cannot detect even periodic beacons at this sequence length.")
        sys.exit(1)

    print()
    print("RESULTS:")
    print()
    if nonperiodic_missed == n_nonperiodic:
        print(f"  + Non-periodic families: {nonperiodic_missed}/{n_nonperiodic} show NO significant peak")
        print(f"    -> Rayleigh periodogram does not detect these scheduling families")
        print(f"    -> The detection gap extends beyond RITA-style scoring to spectral methods")
    elif nonperiodic_missed > 0:
        detected = n_nonperiodic - nonperiodic_missed
        print(f"  ~ Non-periodic families: {nonperiodic_missed}/{n_nonperiodic} show no significant peak")
        print(f"    -> {detected} families DO produce spectral peaks -- investigate before claiming spectral evasion")
    else:
        print(f"  X Non-periodic families: all show significant peaks")
        print(f"    -> The spectral blind spot does NOT exist -- these schedules ARE spectrally detectable")

    print()
