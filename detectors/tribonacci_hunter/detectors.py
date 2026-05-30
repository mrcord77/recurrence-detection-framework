"""
detectors.py
------------
Tribonacci Hunter: Two-gate detector for Tribonacci-scheduled C2 beaconing.

Target: C2 beacons where sleep intervals follow a three-term additive
recurrence a[n] = a[n-1] + a[n-2] + a[n-3]. The canonical instance is the
Tribonacci sequence (1, 1, 2, 4, 7, 13, 24, 44...) but the detector targets
the broader family of geometric growth schedules with ratio near the
Tribonacci constant tau = 1.83929...

These schedules evade:
  - RITA / AC-Hunter (no modal interval, growing intervals, same structural
    ceiling as Fibonacci: max RITA score = 0.50 + 0.50/n)
  - Beacon Hunter (ratio ~1.839 is ABOVE Beacon Hunter's acceptance window
    [1.45, 1.80]; Gate 1 rejects it)
  - Prime Hunter (exponential growth, not logarithmic; Gate 1 rejects it)

Two-gate pipeline:

  Gate 1 -- Tribonacci Ratio Test
    Computes consecutive ICI ratios and tests whether they cluster near
    tau = 1.83929 within ±TAU_TOL. Analogous to Beacon Hunter's phi-ratio
    gate but centered on the Tribonacci constant.

  Gate 2 -- Three-Term Additive Recurrence Test
    Tests whether ICI[n+3] ≈ ICI[n+2] + ICI[n+1] + ICI[n] holds across
    all consecutive quadruples, using mean relative error against a
    permutation null. This is the discriminating gate: Fibonacci sequences
    produce ~24% residual (fail), geometric r=2.0 produces 12.5% (pass,
    known boundary), and true Tribonacci produces 0% residual.

    Theoretical residual for geometric ratio r:
      |r³ - r² - r - 1| / r³
    Zero at r = tau (by definition: tau³ = tau² + tau + 1).

Classification labels:
  TRIBONACCI_RECURRENCE_BEACON  -- Both gates pass
  REGULAR_BEACON                -- Constant-interval periodic beacon
  JITTERED_BEACON               -- Jittered periodic, not Tribonacci
  BACKGROUND                    -- No detectable structure
  INSUFFICIENT_DATA             -- Fewer than MIN_INTERVALS connections

All functions are pure: stateless, no I/O, numpy arrays in / dicts out.
"""

import numpy as np
from scipy import stats

# ============================================================
# Constants
# ============================================================

# Tribonacci constant: real root of x³ - x² - x - 1 = 0
# Analogous to phi (golden ratio) for Fibonacci.
# Computed as: (1/3)(1 + cbrt(19 - 3√33) + cbrt(19 + 3√33))
TAU = 1.8392867552141612  # OEIS A058265

PHI = (1.0 + np.sqrt(5.0)) / 2.0  # 1.618... for cross-family rejection

MIN_INTERVALS       = 5      # minimum ICIs required
TAU_TOL             = 0.15   # max |r_bar - tau| for Gate 1
                             # Window: [1.689, 1.989]
                             # Excludes geometric x2.0 (delta=0.161 > 0.15)
MIN_RATIO           = 1.50   # min r_bar (excludes near-constant schedules)
MAX_RATIO_CV        = 0.50   # max CV of ratios (filters noisy clusters)
RECURRENCE_THRESHOLD = 0.20  # max mean relative error for Gate 2
MAX_P               = 0.05   # max permutation p-value
N_BOOTSTRAP         = 500    # permutation iterations


# ============================================================
# Verify Tribonacci constant
# ============================================================

def _verify_tau():
    """Verify TAU satisfies x³ = x² + x + 1."""
    residual = abs(TAU**3 - TAU**2 - TAU - 1)
    assert residual < 1e-10, f"TAU verification failed: residual={residual}"

_verify_tau()


# ============================================================
# Gate 1: Tribonacci Ratio Test
# ============================================================

def tribonacci_ratio_test(conn_times, tau_tol=TAU_TOL, min_ratio=MIN_RATIO,
                          max_ratio_cv=MAX_RATIO_CV):
    """
    Gate 1: Test whether consecutive ICI ratios cluster near the
    Tribonacci constant tau ≈ 1.8393.

    Theoretical basis: For any sequence satisfying a[n] = a[n-1] + a[n-2]
    + a[n-3], the ratio a[n+1]/a[n] converges to tau, the real root of
    x³ - x² - x - 1 = 0. This is the three-term analogue of Fibonacci
    ratio convergence to phi.

    Parameters
    ----------
    conn_times   : array-like  (connection timestamps)
    tau_tol      : float  (max |r_bar - tau|, default 0.20)
    min_ratio    : float  (min r_bar, default 1.50)
    max_ratio_cv : float  (max CV of ratios, default 0.50)

    Returns
    -------
    dict with keys:
        n_connections, ici_mean, ici_cv, r_bar, delta_tau, ratio_cv,
        label ('TRIBONACCI' | 'PHI_RANGE' | 'REGULAR' | 'JITTERED' |
               'IRREGULAR' | 'INSUFFICIENT'),
        beacon_score (0.0-1.0)
    """
    ct = np.array(sorted(conn_times), dtype=float)
    n = len(ct)

    base = {
        "n_connections": n, "ici_mean": None, "ici_cv": None,
        "r_bar": None, "delta_tau": None, "ratio_cv": None,
        "label": "INSUFFICIENT", "beacon_score": 0.0,
    }

    # Require at least MIN_INTERVALS + 1 timestamps
    if n < MIN_INTERVALS + 1:
        return base

    icis = np.diff(ct)

    # Remove zero/near-zero ICIs
    valid = icis[icis > 1e-6]
    if len(valid) < 3:
        base["label"] = "DEGENERATE"
        return base

    ratios = valid[1:] / valid[:-1]
    r_bar = float(ratios.mean())
    delta_tau = float(abs(r_bar - TAU))
    ratio_cv = float(ratios.std() / max(abs(r_bar), 1e-10))
    ici_cv = float(valid.std() / max(valid.mean(), 1e-10))

    result = {
        "n_connections": n,
        "ici_mean": float(valid.mean()),
        "ici_cv": ici_cv,
        "r_bar": r_bar,
        "delta_tau": delta_tau,
        "ratio_cv": ratio_cv,
    }

    # Check if ratio is near phi instead of tau (belongs to Beacon Hunter)
    delta_phi = abs(r_bar - PHI)
    if delta_phi < 0.20 and delta_tau > tau_tol:
        result["label"] = "PHI_RANGE"
        result["beacon_score"] = 0.0
        return result

    if delta_tau < tau_tol and r_bar > min_ratio and ratio_cv < max_ratio_cv:
        label = "TRIBONACCI"
        score = float(max(0.0, 1.0 - delta_tau / tau_tol))
    elif ici_cv < 0.1:
        label = "REGULAR"
        score = 0.0
    elif ici_cv < 0.4:
        label = "JITTERED"
        score = 0.0
    else:
        label = "IRREGULAR"
        score = 0.0

    result["label"] = label
    result["beacon_score"] = score
    return result


# ============================================================
# Gate 2: Three-Term Additive Recurrence Test
# ============================================================

def tribonacci_recurrence_test(conn_times, n_bootstrap=N_BOOTSTRAP,
                                min_icis=MIN_INTERVALS,
                                max_rel_err=RECURRENCE_THRESHOLD,
                                max_p=MAX_P):
    """
    Gate 2: Three-term additive recurrence test.

    Tests whether inter-connection intervals satisfy:
        ICI[n+3] ≈ ICI[n+2] + ICI[n+1] + ICI[n]

    For a true Tribonacci beacon: residual = 0.
    For geometric ratio r: residual = |r³ - r² - r - 1| / r³
        r = tau (1.839): 0.000  (pass — Tribonacci)
        r = phi (1.618): 0.236  (fail — Fibonacci family)
        r = 2.0:         0.125  (pass — known boundary case)
        r = 1.5:         0.407  (fail)
        r = 2.2:         0.245  (fail)

    Bootstrap null: permuted ICI orderings.

    Parameters
    ----------
    conn_times  : array-like
    n_bootstrap : int         (permutation iterations, default 500)
    max_rel_err : float       (max mean relative residual, default 0.20)
    max_p       : float       (max bootstrap p-value, default 0.05)

    Returns
    -------
    dict with keys:
        mean_rel_err, p_value, label, beacon_score
    """
    ct = np.array(sorted(conn_times), dtype=float)
    icis = np.diff(ct)
    valid = icis[icis > 1e-6]

    base = {
        "mean_rel_err": None, "p_value": None,
        "label": "INSUFFICIENT", "beacon_score": 0.0,
    }

    # Need at least 4 ICIs to form one quadruple for the three-term test
    if len(valid) < 4:
        return base

    # Three-term recurrence: ICI[n+3] ≈ ICI[n+2] + ICI[n+1] + ICI[n]
    predicted = valid[2:-1] + valid[1:-2] + valid[:-3]  # sum of three
    actual = valid[3:]                                    # the fourth term
    rel_err = np.abs(actual - predicted) / np.maximum(actual, 1e-10)
    mean_err = float(rel_err.mean())

    # Bootstrap p-value
    rng = np.random.default_rng(0)
    extreme = 0
    for _ in range(n_bootstrap):
        perm = rng.permutation(valid)
        pred_p = perm[2:-1] + perm[1:-2] + perm[:-3]
        act_p = perm[3:]
        err_p = np.abs(act_p - pred_p) / np.maximum(act_p, 1e-10)
        if err_p.mean() <= mean_err:
            extreme += 1
    p_value = float(extreme / n_bootstrap)

    result = {"mean_rel_err": mean_err, "p_value": p_value}

    if mean_err < max_rel_err and p_value < max_p:
        label = "TRIBONACCI"
        score = float(max(0.0, 1.0 - mean_err / max_rel_err))
    else:
        label = "NOT_TRIBONACCI_RECURRENCE"
        score = 0.0

    result["label"] = label
    result["beacon_score"] = score
    return result


# ============================================================
# classify_flow: end-to-end pipeline
# ============================================================

def classify_flow(timestamps, session_gap=5.0, min_pkts=MIN_INTERVALS,
                  connection_level=False):
    """
    Full two-gate classification pipeline for Tribonacci-scheduled beacons.

    Classification hierarchy:
      TRIBONACCI_RECURRENCE_BEACON — both gates pass
      REGULAR_BEACON — constant-interval periodic
      JITTERED_BEACON — jittered periodic
      BACKGROUND — no detectable structure
      INSUFFICIENT_DATA — fewer than min_pkts timestamps

    Parameters
    ----------
    timestamps       : list or array of connection timestamps
    session_gap      : float  (unused; retained for API compatibility)
    min_pkts         : int    (minimum timestamps to classify)
    connection_level : bool   (True if timestamps are already connection-level)

    Returns
    -------
    dict with classification, confidence, n_connections, gate1, gate2
    """
    ts = sorted(timestamps)
    n = len(ts)

    if n < min_pkts + 1:
        return {
            "classification": "INSUFFICIENT_DATA",
            "confidence":      0.0,
            "n_connections":   n,
            "gate1":           None,
            "gate2":           None,
        }

    icis = np.diff(ts)
    icis_pos = icis[icis > 0]

    # Pre-filter: constant-interval beacons (CV < 0.05)
    if len(icis_pos) >= min_pkts:
        cv = float(np.std(icis_pos) / np.mean(icis_pos)) if np.mean(icis_pos) > 0 else 0
        if cv < 0.05:
            return {
                "classification": "REGULAR_BEACON",
                "confidence":      1.0,
                "n_connections":   n,
                "gate1":           None,
                "gate2":           None,
            }

    # ---- Gate 1: Tribonacci Ratio Test ----
    g1 = tribonacci_ratio_test(ts)

    if g1["label"] == "INSUFFICIENT" or g1["label"] == "DEGENERATE":
        return {
            "classification": "INSUFFICIENT_DATA",
            "confidence":      0.0,
            "n_connections":   n,
            "gate1":           g1,
            "gate2":           None,
        }

    if g1["label"] != "TRIBONACCI":
        # Not in Tribonacci ratio range — classify as periodic or background
        if g1.get("ici_cv") is not None and g1["ici_cv"] < 0.4:
            return {
                "classification": "JITTERED_BEACON",
                "confidence":      0.80,
                "n_connections":   n,
                "gate1":           g1,
                "gate2":           None,
            }
        return {
            "classification": "BACKGROUND",
            "confidence":      1.0,
            "n_connections":   n,
            "gate1":           g1,
            "gate2":           None,
        }

    # ---- Gate 2: Three-Term Additive Recurrence ----
    g2 = tribonacci_recurrence_test(ts)

    if g2["label"] == "TRIBONACCI":
        # Gate 2.5: Convergence verification.
        # Reject geometric backoff where ratios don't converge toward tau.
        is_backoff = False
        icis_check = np.diff(np.array(sorted(ts), dtype=float))
        icis_pos = icis_check[icis_check > 1e-6]
        if len(icis_pos) >= 5:
            c_ratios = icis_pos[1:] / icis_pos[:-1]
            if len(c_ratios) >= 4:
                deviations = np.abs(c_ratios - TAU)
                slope = float(stats.linregress(
                    np.arange(len(deviations)), deviations).slope)
                is_backoff = slope >= -0.008

        if is_backoff:
            return {
                "classification": "BACKGROUND",
                "confidence":      1.0,
                "n_connections":   n,
                "gate1":           g1,
                "gate2":           g2,
            }

        conf = float((g1["beacon_score"] + g2["beacon_score"]) / 2.0)
        return {
            "classification": "TRIBONACCI_RECURRENCE_BEACON",
            "confidence":      round(conf, 3),
            "n_connections":   n,
            "gate1":           g1,
            "gate2":           g2,
        }

    # Gate 1 passed but Gate 2 failed — ratio near tau but recurrence
    # structure not confirmed
    return {
        "classification": "BACKGROUND",
        "confidence":      1.0,
        "n_connections":   n,
        "gate1":           g1,
        "gate2":           g2,
    }


# ============================================================
# Theoretical residual calculator (for validation / boundary sweep)
# ============================================================

def theoretical_residual(r):
    """
    Theoretical three-term recurrence residual for geometric ratio r.
    |r³ - r² - r - 1| / r³
    Zero at r = tau; increases away from tau in both directions.
    """
    return abs(r**3 - r**2 - r - 1) / r**3
