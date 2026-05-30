"""
detectors.py
------------
Narayana Hunter: Two-gate detector for Narayana-scheduled C2 beaconing.

Target: C2 beacons where sleep intervals follow the delayed additive
recurrence a(n) = a(n-1) + a(n-3). The canonical instance is Narayana's
cows sequence (1, 1, 1, 2, 3, 4, 6, 9, 13, 19, 28, 41...) with ratio
converging to the Narayana constant N ≈ 1.4656 (real root of x³ = x² + 1).

Strategic significance: N ≈ 1.466 sits at the LOWER BOUNDARY of Beacon
Hunter's acceptance window [1.45, 1.80]. A Narayana-scheduled beacon
would produce inconsistent alerts from Beacon Hunter — sometimes flagged,
sometimes missed, depending on sequence length and jitter. A dedicated
detector provides reliable classification.

The recurrence is structurally distinct from all other families:
  - Fibonacci:    a(n) = a(n-1) + a(n-2)    (adjacent, skip none)
  - Tribonacci:   a(n) = a(n-1) + a(n-2) + a(n-3)  (three consecutive)
  - Padovan:      a(n) = a(n-2) + a(n-3)    (skip n-1)
  - Narayana:     a(n) = a(n-1) + a(n-3)    (skip n-2)

Each family uses a different subset of previous terms, producing a
different characteristic equation and convergent ratio.

Two-gate pipeline:

  Gate 1 -- Narayana Ratio Test
    Tests ratio convergence near N ≈ 1.4656 within ±NAR_TOL.

  Gate 2 -- Delayed Additive Recurrence Test
    Tests: ICI[n] ≈ ICI[n-1] + ICI[n-3]  (skip n-2)
    Theoretical residual for geometric ratio r: |r³ - r² - 1| / r³
    Zero at r = N.

Classification labels:
  NARAYANA_RECURRENCE_BEACON  -- Both gates pass
  REGULAR_BEACON              -- Constant-interval periodic
  JITTERED_BEACON             -- Jittered periodic
  BACKGROUND                  -- No detectable structure
  INSUFFICIENT_DATA           -- Fewer than MIN_INTERVALS connections

All functions are pure: stateless, no I/O, numpy arrays in / dicts out.
"""

import numpy as np
from scipy import stats

# ============================================================
# Constants
# ============================================================

# Narayana constant: real root of x³ - x² - 1 = 0  (x³ = x² + 1)
# The ratio limit of Narayana's cows sequence.
NAR = 1.4655712318767680  # OEIS A092526

PHI = (1.0 + np.sqrt(5.0)) / 2.0   # 1.618...
TAU = 1.8392867552141612            # Tribonacci constant
RHO = 1.3247179572447460            # Plastic constant (Padovan)

MIN_INTERVALS        = 5
NAR_TOL              = 0.12   # max |r_bar - N| for Gate 1
                               # Window: [1.346, 1.586]
                               # Excludes phi (1.618, delta=0.152)
                               # Excludes rho (1.325, delta=0.141)
MIN_RATIO            = 1.20   # min r_bar
MAX_RATIO_CV         = 0.50   # max CV of ratios
RECURRENCE_THRESHOLD = 0.20   # max mean relative error for Gate 2
MAX_P                = 0.05   # max permutation p-value
N_BOOTSTRAP          = 500    # permutation iterations


# ============================================================
# Verify Narayana constant
# ============================================================

def _verify_nar():
    """Verify NAR satisfies x³ = x² + 1."""
    residual = abs(NAR**3 - NAR**2 - 1)
    assert residual < 1e-10, f"NAR verification failed: residual={residual}"

_verify_nar()


# ============================================================
# Gate 1: Narayana Ratio Test
# ============================================================

def narayana_ratio_test(conn_times, nar_tol=NAR_TOL, min_ratio=MIN_RATIO,
                        max_ratio_cv=MAX_RATIO_CV):
    """
    Gate 1: Test whether consecutive ICI ratios cluster near the
    Narayana constant N ≈ 1.4656.

    Parameters
    ----------
    conn_times   : array-like  (connection timestamps)
    nar_tol      : float  (max |r_bar - N|, default 0.12)
    min_ratio    : float  (min r_bar, default 1.20)
    max_ratio_cv : float  (max CV of ratios, default 0.50)

    Returns
    -------
    dict with keys: n_connections, ici_mean, ici_cv, r_bar, delta_nar,
                    ratio_cv, label, beacon_score
    """
    ct = np.array(sorted(conn_times), dtype=float)
    n = len(ct)

    base = {
        "n_connections": n, "ici_mean": None, "ici_cv": None,
        "r_bar": None, "delta_nar": None, "ratio_cv": None,
        "label": "INSUFFICIENT", "beacon_score": 0.0,
    }

    if n < MIN_INTERVALS + 1:
        return base

    icis = np.diff(ct)
    valid = icis[icis > 1e-6]
    if len(valid) < 3:
        base["label"] = "DEGENERATE"
        return base

    ratios = valid[1:] / valid[:-1]
    r_bar = float(ratios.mean())
    delta_nar = float(abs(r_bar - NAR))
    ratio_cv = float(ratios.std() / max(abs(r_bar), 1e-10))
    ici_cv = float(valid.std() / max(valid.mean(), 1e-10))

    result = {
        "n_connections": n,
        "ici_mean": float(valid.mean()),
        "ici_cv": ici_cv,
        "r_bar": r_bar,
        "delta_nar": delta_nar,
        "ratio_cv": ratio_cv,
    }

    # Cross-family rejection
    delta_phi = abs(r_bar - PHI)
    delta_tau = abs(r_bar - TAU)
    delta_rho = abs(r_bar - RHO)

    if delta_phi < 0.12 and delta_nar > nar_tol:
        result["label"] = "PHI_RANGE"
        result["beacon_score"] = 0.0
        return result
    if delta_tau < 0.15 and delta_nar > nar_tol:
        result["label"] = "TAU_RANGE"
        result["beacon_score"] = 0.0
        return result
    if delta_rho < 0.10 and delta_nar > nar_tol:
        result["label"] = "RHO_RANGE"
        result["beacon_score"] = 0.0
        return result

    if delta_nar < nar_tol and r_bar > min_ratio and ratio_cv < max_ratio_cv:
        label = "NARAYANA"
        score = float(max(0.0, 1.0 - delta_nar / nar_tol))
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
# Gate 2: Delayed Additive Recurrence Test
# ============================================================

def narayana_recurrence_test(conn_times, n_bootstrap=N_BOOTSTRAP,
                              min_icis=MIN_INTERVALS,
                              max_rel_err=RECURRENCE_THRESHOLD,
                              max_p=MAX_P):
    """
    Gate 2: Delayed additive recurrence test.

    Tests: ICI[n] ≈ ICI[n-1] + ICI[n-3]

    Structurally distinct from:
      Fibonacci:   ICI[n] = ICI[n-1] + ICI[n-2]
      Tribonacci:  ICI[n] = ICI[n-1] + ICI[n-2] + ICI[n-3]
      Padovan:     ICI[n] = ICI[n-2] + ICI[n-3]
      Narayana:    ICI[n] = ICI[n-1] + ICI[n-3]  ← THIS ONE (skip n-2)

    Theoretical residual for geometric ratio r:
      |r³ - r² - 1| / r³

        r = N (1.466):   0.000  (pass — Narayana)
        r = 1.5:         0.037  (pass — known boundary)
        r = 1.4:         0.079  (pass)
        r = phi (1.618): 0.146  (pass — but Gate 1 rejects phi)
        r = rho (1.325): 0.185  (pass — but Gate 1 rejects rho)
        r = 1.7:         0.208  (fail)
        r = tau (1.839): 0.296  (fail)
        r = 2.0:         0.375  (fail)

    Parameters
    ----------
    conn_times  : array-like
    n_bootstrap : int
    max_rel_err : float
    max_p       : float

    Returns
    -------
    dict with keys: mean_rel_err, p_value, label, beacon_score
    """
    ct = np.array(sorted(conn_times), dtype=float)
    icis = np.diff(ct)
    valid = icis[icis > 1e-6]

    base = {
        "mean_rel_err": None, "p_value": None,
        "label": "INSUFFICIENT", "beacon_score": 0.0,
    }

    # Need at least 4 ICIs: ICI[3] ≈ ICI[2] + ICI[0]
    if len(valid) < 4:
        return base

    # Delayed recurrence: ICI[n] ≈ ICI[n-1] + ICI[n-3]
    actual = valid[3:]           # ICI[3], ICI[4], ...
    predicted = valid[2:-1] + valid[:-3]  # ICI[n-1] + ICI[n-3]
    rel_err = np.abs(actual - predicted) / np.maximum(actual, 1e-10)
    mean_err = float(rel_err.mean())

    # Bootstrap p-value
    rng = np.random.default_rng(0)
    extreme = 0
    for _ in range(n_bootstrap):
        perm = rng.permutation(valid)
        pred_p = perm[2:-1] + perm[:-3]
        act_p = perm[3:]
        err_p = np.abs(act_p - pred_p) / np.maximum(act_p, 1e-10)
        if err_p.mean() <= mean_err:
            extreme += 1
    p_value = float(extreme / n_bootstrap)

    result = {"mean_rel_err": mean_err, "p_value": p_value}

    if mean_err < max_rel_err and p_value < max_p:
        label = "NARAYANA"
        score = float(max(0.0, 1.0 - mean_err / max_rel_err))
    else:
        label = "NOT_NARAYANA_RECURRENCE"
        score = 0.0

    result["label"] = label
    result["beacon_score"] = score
    return result


# ============================================================
# classify_flow
# ============================================================

def classify_flow(timestamps, session_gap=5.0, min_pkts=MIN_INTERVALS,
                  connection_level=False):
    """Full two-gate pipeline for Narayana-scheduled beacons."""
    ts = sorted(timestamps)
    n = len(ts)

    if n < min_pkts + 1:
        return {"classification": "INSUFFICIENT_DATA", "confidence": 0.0,
                "n_connections": n, "gate1": None, "gate2": None}

    icis = np.diff(ts)
    icis_pos = icis[icis > 0]
    if len(icis_pos) >= min_pkts:
        cv = float(np.std(icis_pos) / np.mean(icis_pos)) if np.mean(icis_pos) > 0 else 0
        if cv < 0.05:
            return {"classification": "REGULAR_BEACON", "confidence": 1.0,
                    "n_connections": n, "gate1": None, "gate2": None}

    g1 = narayana_ratio_test(ts)

    if g1["label"] in ("INSUFFICIENT", "DEGENERATE"):
        return {"classification": "INSUFFICIENT_DATA", "confidence": 0.0,
                "n_connections": n, "gate1": g1, "gate2": None}

    if g1["label"] != "NARAYANA":
        if g1.get("ici_cv") is not None and g1["ici_cv"] < 0.4:
            return {"classification": "JITTERED_BEACON", "confidence": 0.80,
                    "n_connections": n, "gate1": g1, "gate2": None}
        return {"classification": "BACKGROUND", "confidence": 1.0,
                "n_connections": n, "gate1": g1, "gate2": None}

    g2 = narayana_recurrence_test(ts)

    if g2["label"] == "NARAYANA":
        # Gate 2.5: Convergence verification.
        # Reject geometric backoff where ratios don't converge toward N.
        is_backoff = False
        icis_check = np.diff(np.array(sorted(ts), dtype=float))
        icis_pos = icis_check[icis_check > 1e-6]
        if len(icis_pos) >= 5:
            c_ratios = icis_pos[1:] / icis_pos[:-1]
            if len(c_ratios) >= 4:
                deviations = np.abs(c_ratios - NAR)
                slope = float(stats.linregress(
                    np.arange(len(deviations)), deviations).slope)
                is_backoff = slope >= -0.008

        if not is_backoff:
            conf = float((g1["beacon_score"] + g2["beacon_score"]) / 2.0)
            return {"classification": "NARAYANA_RECURRENCE_BEACON",
                    "confidence": round(conf, 3),
                    "n_connections": n, "gate1": g1, "gate2": g2}

    return {"classification": "BACKGROUND", "confidence": 1.0,
            "n_connections": n, "gate1": g1, "gate2": g2}


# ============================================================
# Theoretical residual
# ============================================================

def theoretical_residual(r):
    """Theoretical residual |r³ - r² - 1| / r³. Zero at r = N."""
    return abs(r**3 - r**2 - 1) / r**3
