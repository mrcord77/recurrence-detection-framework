"""
detectors.py
------------
Padovan Hunter: Two-gate detector for Padovan-scheduled C2 beaconing.

Target: C2 beacons where sleep intervals follow the non-adjacent additive
recurrence P(n) = P(n-2) + P(n-3). The canonical instance is the Padovan
sequence (1, 1, 1, 2, 2, 3, 4, 5, 7, 9, 12, 16, 21, 28...) but the
detector targets the broader family of geometric growth schedules with
ratio near the plastic constant rho = 1.32472...

These schedules evade ALL existing detector families:
  - RITA / AC-Hunter    (growing intervals, structural ceiling applies)
  - Beacon Hunter       (ratio ~1.325 is BELOW acceptance window [1.45, 1.80])
  - Prime Hunter        (exponential growth, not logarithmic)
  - Tribonacci Hunter   (ratio ~1.325 is BELOW acceptance window [1.689, 1.989])

Operational advantage for the attacker: the plastic constant (~1.325) is
the slowest-growing recurrence ratio in this family. Intervals increase
~32% per step vs ~62% (Fibonacci) or ~84% (Tribonacci), producing more
callback events before intervals become impractically large.

Two-gate pipeline:

  Gate 1 -- Plastic Ratio Test
    Computes consecutive ICI ratios and tests whether they cluster near
    rho = 1.32472 within ±RHO_TOL.

  Gate 2 -- Non-Adjacent Additive Recurrence Test
    Tests whether ICI[n] ≈ ICI[n-2] + ICI[n-3] holds across all testable
    positions, using mean relative error against a permutation null.

    Theoretical residual for geometric ratio r:
      |r³ - r - 1| / r³
    Zero at r = rho (by definition: rho³ = rho + 1).

Classification labels:
  PADOVAN_RECURRENCE_BEACON  -- Both gates pass
  REGULAR_BEACON             -- Constant-interval periodic beacon
  JITTERED_BEACON            -- Jittered periodic, not Padovan-structured
  BACKGROUND                 -- No detectable structure
  INSUFFICIENT_DATA          -- Fewer than MIN_INTERVALS connections

All functions are pure: stateless, no I/O, numpy arrays in / dicts out.
"""

import numpy as np
from scipy import stats

# ============================================================
# Constants
# ============================================================

# Plastic constant: real root of x³ - x - 1 = 0  (equivalently x³ = x + 1)
# The Padovan sequence ratio limit, analogous to phi for Fibonacci
# and tau for Tribonacci.
RHO = 1.3247179572447460  # OEIS A060006

PHI = (1.0 + np.sqrt(5.0)) / 2.0   # 1.618... for cross-family rejection
TAU = 1.8392867552141612            # Tribonacci constant

MIN_INTERVALS        = 5      # minimum ICIs required
RHO_TOL              = 0.15   # max |r_bar - rho| for Gate 1
                               # Window: [1.175, 1.475]
MIN_RATIO            = 1.10   # min r_bar (excludes near-constant schedules)
MAX_RATIO_CV         = 0.55   # max CV of ratios (Padovan has early oscillation)
RECURRENCE_THRESHOLD = 0.20   # max mean relative error for Gate 2
MAX_P                = 0.05   # max permutation p-value
N_BOOTSTRAP          = 500    # permutation iterations


# ============================================================
# Verify plastic constant
# ============================================================

def _verify_rho():
    """Verify RHO satisfies x³ = x + 1."""
    residual = abs(RHO**3 - RHO - 1)
    assert residual < 1e-10, f"RHO verification failed: residual={residual}"

_verify_rho()


# ============================================================
# Gate 1: Plastic Ratio Test
# ============================================================

def padovan_ratio_test(conn_times, rho_tol=RHO_TOL, min_ratio=MIN_RATIO,
                       max_ratio_cv=MAX_RATIO_CV):
    """
    Gate 1: Test whether consecutive ICI ratios cluster near the
    plastic constant rho ≈ 1.3247.

    The Padovan sequence has slower ratio convergence than Fibonacci or
    Tribonacci due to the non-adjacent recurrence structure. Early terms
    (1, 1, 1, 2, 2, 3...) produce ratios that oscillate before settling.
    The MAX_RATIO_CV is set higher (0.55) to accommodate this.

    Parameters
    ----------
    conn_times   : array-like  (connection timestamps)
    rho_tol      : float  (max |r_bar - rho|, default 0.15)
    min_ratio    : float  (min r_bar, default 1.10)
    max_ratio_cv : float  (max CV of ratios, default 0.55)

    Returns
    -------
    dict with keys:
        n_connections, ici_mean, ici_cv, r_bar, delta_rho, ratio_cv,
        label, beacon_score
    """
    ct = np.array(sorted(conn_times), dtype=float)
    n = len(ct)

    base = {
        "n_connections": n, "ici_mean": None, "ici_cv": None,
        "r_bar": None, "delta_rho": None, "ratio_cv": None,
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
    delta_rho = float(abs(r_bar - RHO))
    ratio_cv = float(ratios.std() / max(abs(r_bar), 1e-10))
    ici_cv = float(valid.std() / max(valid.mean(), 1e-10))

    result = {
        "n_connections": n,
        "ici_mean": float(valid.mean()),
        "ici_cv": ici_cv,
        "r_bar": r_bar,
        "delta_rho": delta_rho,
        "ratio_cv": ratio_cv,
    }

    # Cross-family rejection: if ratio is near phi or tau, it belongs
    # to Beacon Hunter or Tribonacci Hunter, not Padovan Hunter
    delta_phi = abs(r_bar - PHI)
    delta_tau = abs(r_bar - TAU)
    if delta_phi < 0.20 and delta_rho > rho_tol:
        result["label"] = "PHI_RANGE"
        result["beacon_score"] = 0.0
        return result
    if delta_tau < 0.20 and delta_rho > rho_tol:
        result["label"] = "TAU_RANGE"
        result["beacon_score"] = 0.0
        return result

    if delta_rho < rho_tol and r_bar > min_ratio and ratio_cv < max_ratio_cv:
        label = "PADOVAN"
        score = float(max(0.0, 1.0 - delta_rho / rho_tol))
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
# Gate 2: Non-Adjacent Additive Recurrence Test
# ============================================================

def padovan_recurrence_test(conn_times, n_bootstrap=N_BOOTSTRAP,
                            min_icis=MIN_INTERVALS,
                            max_rel_err=RECURRENCE_THRESHOLD,
                            max_p=MAX_P):
    """
    Gate 2: Non-adjacent additive recurrence test.

    Tests whether inter-connection intervals satisfy the Padovan recurrence:
        ICI[n] ≈ ICI[n-2] + ICI[n-3]

    This is structurally distinct from:
      - Fibonacci:   ICI[n] = ICI[n-1] + ICI[n-2]  (adjacent, 2-term)
      - Tribonacci:  ICI[n] = ICI[n-1] + ICI[n-2] + ICI[n-3]  (adjacent, 3-term)
      - Padovan:     ICI[n] = ICI[n-2] + ICI[n-3]  (NON-ADJACENT, skip n-1)

    Theoretical residual for geometric ratio r:
      |r³ - r - 1| / r³
    (derived from: r^n should equal r^(n-2) + r^(n-3), dividing by r^(n-3)
     gives r³ = r + 1, which holds exactly at r = rho)

        r = rho (1.325): 0.000  (pass — Padovan)
        r = 1.30:         0.047  (pass — near-rho)
        r = 1.40:         0.125  (pass — boundary)
        r = phi (1.618):  0.382  (fail — Fibonacci family)
        r = tau (1.839):  0.544  (fail — Tribonacci family)
        r = 2.0:          0.625  (fail)
        r = 1.5:          0.259  (fail)

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

    # Need at least 4 ICIs to form one testable position:
    # ICI[3] ≈ ICI[1] + ICI[0]
    if len(valid) < 4:
        return base

    # Non-adjacent recurrence: ICI[n] ≈ ICI[n-2] + ICI[n-3]
    # For each n from 3 to len-1:
    #   actual   = valid[n]       = valid[3:]
    #   predicted = valid[n-2] + valid[n-3] = valid[1:-2] + valid[:-3]
    actual = valid[3:]
    predicted = valid[1:-2] + valid[:-3]
    rel_err = np.abs(actual - predicted) / np.maximum(actual, 1e-10)
    mean_err = float(rel_err.mean())

    # Bootstrap p-value
    rng = np.random.default_rng(0)
    extreme = 0
    for _ in range(n_bootstrap):
        perm = rng.permutation(valid)
        pred_p = perm[1:-2] + perm[:-3]
        act_p = perm[3:]
        err_p = np.abs(act_p - pred_p) / np.maximum(act_p, 1e-10)
        if err_p.mean() <= mean_err:
            extreme += 1
    p_value = float(extreme / n_bootstrap)

    result = {"mean_rel_err": mean_err, "p_value": p_value}

    if mean_err < max_rel_err and p_value < max_p:
        label = "PADOVAN"
        score = float(max(0.0, 1.0 - mean_err / max_rel_err))
    else:
        label = "NOT_PADOVAN_RECURRENCE"
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
    Full two-gate classification pipeline for Padovan-scheduled beacons.

    Classification hierarchy:
      PADOVAN_RECURRENCE_BEACON — both gates pass
      REGULAR_BEACON — constant-interval periodic
      JITTERED_BEACON — jittered periodic
      BACKGROUND — no detectable structure
      INSUFFICIENT_DATA — fewer than min_pkts timestamps
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

    # ---- Gate 1: Plastic Ratio Test ----
    g1 = padovan_ratio_test(ts)

    if g1["label"] in ("INSUFFICIENT", "DEGENERATE"):
        return {
            "classification": "INSUFFICIENT_DATA",
            "confidence":      0.0,
            "n_connections":   n,
            "gate1":           g1,
            "gate2":           None,
        }

    if g1["label"] != "PADOVAN":
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

    # ---- Gate 2: Non-Adjacent Recurrence ----
    g2 = padovan_recurrence_test(ts)

    if g2["label"] == "PADOVAN":
        # Gate 2.5: Convergence verification.
        is_backoff = False
        icis_check = np.diff(np.array(sorted(ts), dtype=float))
        icis_pos = icis_check[icis_check > 1e-6]
        if len(icis_pos) >= 5:
            c_ratios = icis_pos[1:] / icis_pos[:-1]
            if len(c_ratios) >= 4:
                deviations = np.abs(c_ratios - RHO)
                slope = float(stats.linregress(
                    np.arange(len(deviations)), deviations).slope)
                is_backoff = slope >= -0.008

        if not is_backoff:
            conf = float((g1["beacon_score"] + g2["beacon_score"]) / 2.0)
            return {
                "classification": "PADOVAN_RECURRENCE_BEACON",
                "confidence":      round(conf, 3),
                "n_connections":   n,
                "gate1":           g1,
                "gate2":           g2,
            }

    return {
        "classification": "BACKGROUND",
        "confidence":      1.0,
        "n_connections":   n,
        "gate1":           g1,
        "gate2":           g2,
    }


# ============================================================
# Theoretical residual calculator
# ============================================================

def theoretical_residual(r):
    """
    Theoretical Padovan recurrence residual for geometric ratio r.
    |r³ - r - 1| / r³
    Zero at r = rho (plastic constant); increases away from rho.
    """
    return abs(r**3 - r - 1) / r**3
