"""
detectors.py
------------
Reverse Scanner v1.2: Consolidated detector for the 4 algebraic recurrence
families, tested in BOTH forward and reverse ICI order.

Forward detection catches growing-interval schedules (Fibonacci, Tribonacci,
Padovan, Narayana).

Reverse detection catches SHRINKING-interval schedules — the same
mathematical families run backward. An attacker using reverse-Fibonacci
(21, 13, 8, 5, 3, 2 seconds) starts slow and accelerates: low-profile
during initial compromise, high-frequency during active exfiltration.

Architecture:
  1. Compute ICIs from timestamps
  2. Test ICIs against 4 recurrence families (forward)
  3. Reverse the ICI sequence and test again (reverse)
  4. Report best match with direction label

Note: Prime and polynomial detection paths were removed in v1.2 after
large-scale validation on the CTU-13 dataset (251K flows) demonstrated
that prime-adjacency is not a sufficiently discriminative signal — 98%
of all structural false positives originated from the prime detection path.
The recurrence families test structural relationships between consecutive
intervals; prime detection tests individual interval values. These are
fundamentally different signal types.

All functions are pure: stateless, no I/O.
"""

import numpy as np
from scipy import stats as sp_stats

# ============================================================
# Mathematical Constants
# ============================================================

PHI = (1.0 + np.sqrt(5.0)) / 2.0       # 1.6180... Golden ratio (Fibonacci)
TAU = 1.8392867552141612                # Tribonacci constant
RHO = 1.3247179572447460                # Plastic constant (Padovan)
NAR = 1.4655712318767680                # Narayana constant

MIN_INTERVALS = 5
N_BOOTSTRAP = 300
CONVERGENCE_SLOPE_THRESHOLD = -0.008  # Ratios must converge toward constant


# ============================================================
# Geometric Backoff Rejection
# ============================================================

def _is_geometric_backoff(ratios, constant):
    """
    Test whether consecutive ratios show convergence toward the family
    constant (true recurrence) or are scattered around it (geometric backoff).

    True recurrence: early ratios deviate from constant, later ratios converge.
    Slope of |ratio - constant| vs index is NEGATIVE (converging).

    Geometric backoff: ratios are randomly distributed around a constant
    multiplier. Slope is near zero or positive.

    Returns True if the sequence appears to be geometric backoff (should reject).
    """
    if len(ratios) < 4:
        return False  # Not enough data to assess convergence
    deviations = np.abs(ratios - constant)
    x = np.arange(len(deviations), dtype=float)
    slope, _, _, _, _ = sp_stats.linregress(x, deviations)
    return slope >= CONVERGENCE_SLOPE_THRESHOLD


# ============================================================
# Recurrence families: each returns (mean_rel_err, p_value)
# ============================================================

def _bootstrap_p(valid, compute_err_fn, observed_err, n_boot=N_BOOTSTRAP):
    """Generic permutation p-value."""
    rng = np.random.default_rng(0)
    extreme = 0
    for _ in range(n_boot):
        perm = rng.permutation(valid)
        if compute_err_fn(perm) <= observed_err:
            extreme += 1
    return float(extreme / n_boot)


def fibonacci_recurrence(icis):
    """ICI[n+2] ≈ ICI[n+1] + ICI[n]. Residual 0 at r=phi."""
    if len(icis) < 3:
        return None, None
    predicted = icis[1:-1] + icis[:-2]
    actual = icis[2:]
    rel_err = np.abs(actual - predicted) / np.maximum(actual, 1e-10)
    err = float(rel_err.mean())
    fn = lambda v: float(np.abs(v[2:] - v[1:-1] - v[:-2]).mean() / np.maximum(v[2:], 1e-10).mean())
    p = _bootstrap_p(icis, fn, err)
    return err, p


def tribonacci_recurrence(icis):
    """ICI[n+3] ≈ ICI[n+2] + ICI[n+1] + ICI[n]. Residual 0 at r=tau."""
    if len(icis) < 4:
        return None, None
    predicted = icis[2:-1] + icis[1:-2] + icis[:-3]
    actual = icis[3:]
    rel_err = np.abs(actual - predicted) / np.maximum(actual, 1e-10)
    err = float(rel_err.mean())
    fn = lambda v: float(np.mean(np.abs(v[3:] - v[2:-1] - v[1:-2] - v[:-3]) / np.maximum(v[3:], 1e-10)))
    p = _bootstrap_p(icis, fn, err)
    return err, p


def padovan_recurrence(icis):
    """ICI[n] ≈ ICI[n-2] + ICI[n-3]. Residual 0 at r=rho."""
    if len(icis) < 4:
        return None, None
    actual = icis[3:]
    predicted = icis[1:-2] + icis[:-3]
    rel_err = np.abs(actual - predicted) / np.maximum(actual, 1e-10)
    err = float(rel_err.mean())
    fn = lambda v: float(np.mean(np.abs(v[3:] - v[1:-2] - v[:-3]) / np.maximum(v[3:], 1e-10)))
    p = _bootstrap_p(icis, fn, err)
    return err, p


def narayana_recurrence(icis):
    """ICI[n] ≈ ICI[n-1] + ICI[n-3]. Residual 0 at r=N."""
    if len(icis) < 4:
        return None, None
    actual = icis[3:]
    predicted = icis[2:-1] + icis[:-3]
    rel_err = np.abs(actual - predicted) / np.maximum(actual, 1e-10)
    err = float(rel_err.mean())
    fn = lambda v: float(np.mean(np.abs(v[3:] - v[2:-1] - v[:-3]) / np.maximum(v[3:], 1e-10)))
    p = _bootstrap_p(icis, fn, err)
    return err, p


# ============================================================
# Recurrence family registry
# ============================================================

RECURRENCE_FAMILIES = [
    {
        "name": "FIBONACCI",
        "constant": PHI,
        "constant_name": "φ",
        "tolerance": 0.20,
        "equation": "x² = x + 1",
        "recurrence_fn": fibonacci_recurrence,
        "recurrence_desc": "ICI[n+2] ≈ ICI[n+1] + ICI[n]",
    },
    {
        "name": "TRIBONACCI",
        "constant": TAU,
        "constant_name": "τ",
        "tolerance": 0.15,
        "equation": "x³ = x² + x + 1",
        "recurrence_fn": tribonacci_recurrence,
        "recurrence_desc": "ICI[n+3] ≈ ICI[n+2] + ICI[n+1] + ICI[n]",
    },
    {
        "name": "PADOVAN",
        "constant": RHO,
        "constant_name": "ρ",
        "tolerance": 0.15,
        "equation": "x³ = x + 1",
        "recurrence_fn": padovan_recurrence,
        "recurrence_desc": "ICI[n] ≈ ICI[n-2] + ICI[n-3]",
    },
    {
        "name": "NARAYANA",
        "constant": NAR,
        "constant_name": "N",
        "tolerance": 0.12,
        "equation": "x³ = x² + 1",
        "recurrence_fn": narayana_recurrence,
        "recurrence_desc": "ICI[n] ≈ ICI[n-1] + ICI[n-3]",
    },
]


# ============================================================
# Prime detection (logarithmic growth)
# ============================================================

_PRIMES = []
def _ensure_primes():
    global _PRIMES
    if not _PRIMES:
        limit = 10000
        sieve = bytearray([1]) * (limit + 1)
        sieve[0] = sieve[1] = 0
        for i in range(2, int(limit**0.5) + 1):
            if sieve[i]:
                sieve[i*i::i] = bytearray(len(sieve[i*i::i]))
        _PRIMES = [i for i in range(2, limit + 1) if sieve[i]]

def prime_test(icis, log_fit_threshold=0.30, prime_hit_rate=0.70):
    """Test for consecutive-prime-interval scheduling."""
    _ensure_primes()
    n = len(icis)
    if n < MIN_INTERVALS:
        return None, None, None

    # Gate 1: logarithmic growth fit
    best_err = np.inf
    best_k = 1
    for k in range(1, 60):
        indices = np.arange(k, k + n, dtype=float)
        expected = indices * np.log(indices + 1)
        base = float(np.median(icis / np.maximum(expected, 1e-10)))
        if base <= 0:
            continue
        predicted = base * expected
        rel_err = float(np.mean(np.abs(icis - predicted) / np.maximum(icis, 1e-10)))
        if rel_err < best_err:
            best_err = rel_err
            best_k = k

    if best_err > log_fit_threshold:
        return best_err, None, False

    # Gate 2: prime alignment
    best_start = 1
    best_align_err = np.inf
    best_base = 1.0
    for k in range(1, 50):
        candidate = np.array(_PRIMES[k-1:k-1+n], float)
        if len(candidate) < n:
            break
        base = float(np.median(icis / candidate))
        if base <= 0:
            continue
        rel_errors = np.abs(icis - base * candidate) / np.maximum(icis, 1e-10)
        err = float(np.mean(rel_errors))
        if err < best_align_err:
            best_align_err = err
            best_start = k
            best_base = base

    aligned = np.array(_PRIMES[best_start-1:best_start-1+n], float)
    rel_errors = np.abs(icis - best_base * aligned) / np.maximum(icis, 1e-10)
    hit_rate = float(np.mean(rel_errors <= 0.25))

    return best_err, hit_rate, hit_rate >= prime_hit_rate


# ============================================================
# Polynomial detection (power-law growth)
# ============================================================

def polynomial_test(icis, r2_threshold=0.95, min_alpha=1.5, max_alpha=6.0,
                    fit_threshold=0.20):
    """Test for power-law / polynomial growth."""
    n = len(icis)
    if n < MIN_INTERVALS:
        return None, None, None, False

    log_ici = np.log(np.maximum(icis, 1e-10))
    best_r2 = -np.inf
    best_alpha = None
    for k in range(1, 31):
        indices = np.arange(k, k + n, dtype=float)
        slope, intercept, r, _, _ = sp_stats.linregress(np.log(indices), log_ici)
        r2 = r ** 2
        if r2 > best_r2:
            best_r2 = r2
            best_alpha = slope

    if not (best_r2 >= r2_threshold and best_alpha and min_alpha <= best_alpha <= max_alpha):
        return best_alpha, best_r2, None, False

    # Gate 2: polynomial fit
    best_err = np.inf
    best_k = None
    for deg in range(2, min(5, n)):
        for off in range(1, 21):
            indices = np.arange(off, off + n, dtype=float)
            try:
                coeffs = np.polyfit(indices, icis, deg)
                predicted = np.polyval(coeffs, indices)
                rel_err = np.mean(np.abs(icis - predicted) / np.maximum(np.abs(icis), 1e-10))
                if rel_err < best_err:
                    best_err = float(rel_err)
                    best_k = deg
                if rel_err < fit_threshold * 0.5:
                    break
            except:
                continue

    passes = best_err < fit_threshold
    return best_alpha, best_r2, best_k, passes


# ============================================================
# Core: scan one direction
# ============================================================

def _scan_direction(icis):
    """Test ICIs against all 6 families. Returns list of matches."""
    valid = icis[icis > 1e-6]
    n = len(valid)
    if n < MIN_INTERVALS:
        return []

    matches = []

    # Check constant beacon first
    cv = float(np.std(valid) / np.mean(valid)) if np.mean(valid) > 0 else 0
    if cv < 0.05:
        matches.append({
            "family": "REGULAR_BEACON",
            "confidence": 1.0,
            "details": {"cv": cv},
        })
        return matches

    # Recurrence families (ratio + recurrence test)
    ratios = valid[1:] / valid[:-1]
    r_bar = float(ratios.mean())
    ratio_cv = float(ratios.std() / max(abs(r_bar), 1e-10))

    for fam in RECURRENCE_FAMILIES:
        delta = abs(r_bar - fam["constant"])
        if delta < fam["tolerance"] and r_bar > 1.10 and ratio_cv < 0.55:
            err, p = fam["recurrence_fn"](valid)
            if err is not None and err < 0.20 and p is not None and p < 0.05:
                # Gate 2.5: Reject geometric backoff
                if _is_geometric_backoff(ratios, fam["constant"]):
                    continue
                g1_score = max(0.0, 1.0 - delta / fam["tolerance"])
                g2_score = max(0.0, 1.0 - err / 0.20)
                conf = (g1_score + g2_score) / 2.0
                matches.append({
                    "family": fam["name"],
                    "confidence": round(conf, 3),
                    "details": {
                        "r_bar": r_bar,
                        "delta": round(delta, 4),
                        "constant": fam["constant_name"],
                        "rec_err": round(err, 4),
                        "p_value": round(p, 4),
                        "equation": fam["equation"],
                    },
                })

    # Prime test
    log_err, hit_rate, prime_pass = prime_test(valid)
    if prime_pass:
        conf = min(1.0, hit_rate) * 0.8 if hit_rate else 0.5
        matches.append({
            "family": "PRIME_SEQUENCE",
            "confidence": round(conf, 3),
            "details": {"log_fit_err": round(log_err, 4), "hit_rate": round(hit_rate, 4)},
        })

    # Polynomial test
    alpha, r2, degree, poly_pass = polynomial_test(valid)
    if poly_pass:
        conf = min(1.0, r2) * 0.7 if r2 else 0.5
        matches.append({
            "family": "POLYNOMIAL",
            "confidence": round(conf, 3),
            "details": {"alpha": round(alpha, 3), "r_squared": round(r2, 4), "degree": degree},
        })

    return matches


# ============================================================
# Public API: scan both directions
# ============================================================

def _scan_direction_recurrence_only(icis):
    """Test ICIs against only the 4 recurrence families (for reverse scan)."""
    valid = icis[icis > 1e-6]
    n = len(valid)
    if n < MIN_INTERVALS:
        return []

    cv = float(np.std(valid) / np.mean(valid)) if np.mean(valid) > 0 else 0
    if cv < 0.05:
        return []

    matches = []
    ratios = valid[1:] / valid[:-1]
    r_bar = float(ratios.mean())
    ratio_cv = float(ratios.std() / max(abs(r_bar), 1e-10))

    for fam in RECURRENCE_FAMILIES:
        delta = abs(r_bar - fam["constant"])
        if delta < fam["tolerance"] and r_bar > 1.10 and ratio_cv < 0.55:
            err, p = fam["recurrence_fn"](valid)
            if err is not None and err < 0.20 and p is not None and p < 0.05:
                # Gate 2.5: Reject geometric backoff
                if _is_geometric_backoff(ratios, fam["constant"]):
                    continue
                g1_score = max(0.0, 1.0 - delta / fam["tolerance"])
                g2_score = max(0.0, 1.0 - err / 0.20)
                conf = (g1_score + g2_score) / 2.0
                matches.append({
                    "family": fam["name"],
                    "confidence": round(conf, 3),
                    "details": {
                        "r_bar": r_bar,
                        "delta": round(delta, 4),
                        "constant": fam["constant_name"],
                        "rec_err": round(err, 4),
                        "p_value": round(p, 4),
                        "equation": fam["equation"],
                    },
                })
    return matches


# ============================================================
# Strict Prime Test (for reverse mode)
# ============================================================

def prime_test_strict(icis):
    """Strict prime detection: hit_rate>=0.85, consecutive, permutation sig."""
    _ensure_primes()
    n = len(icis)
    if n < MIN_INTERVALS:
        return None
    best_log_err = np.inf
    for k in range(1, 60):
        indices = np.arange(k, k + n, dtype=float)
        expected = indices * np.log(indices + 1)
        base = float(np.median(icis / np.maximum(expected, 1e-10)))
        if base <= 0: continue
        rel_err = float(np.mean(np.abs(icis - base * expected) / np.maximum(icis, 1e-10)))
        if rel_err < best_log_err: best_log_err = rel_err
    if best_log_err > 0.30:
        return None
    best_start, best_base, best_align_err = 1, 1.0, np.inf
    for k in range(1, 50):
        cand = np.array(_PRIMES[k-1:k-1+n], float)
        if len(cand) < n: break
        base = float(np.median(icis / cand))
        if base <= 0: continue
        err = float(np.mean(np.abs(icis - base * cand) / np.maximum(icis, 1e-10)))
        if err < best_align_err:
            best_align_err, best_start, best_base = err, k, base
    aligned = np.array(_PRIMES[best_start-1:best_start-1+n], float)
    rel_errors = np.abs(icis - best_base * aligned) / np.maximum(icis, 1e-10)
    hits = rel_errors <= 0.25
    hit_rate = float(np.mean(hits))
    if hit_rate < 0.85:
        return None
    hit_idx = [i for i in range(n) if hits[i]]
    if len(hit_idx) < 2: return None
    max_gap = max(hit_idx[i+1] - hit_idx[i] for i in range(len(hit_idx)-1))
    if max_gap > 1: return None
    rng = np.random.default_rng(0)
    extreme = 0
    for _ in range(200):
        perm = rng.permutation(icis)
        pb = float(np.median(perm / aligned))
        if pb <= 0: continue
        if float(np.mean(np.abs(perm - pb * aligned) / np.maximum(perm, 1e-10) <= 0.25)) >= hit_rate:
            extreme += 1
    if extreme / 200 >= 0.05: return None
    return {"family": "PRIME_SEQUENCE", "confidence": round(min(1.0, hit_rate) * 0.8, 3),
            "details": {"hit_rate": round(hit_rate, 4), "p_value": round(extreme/200, 4), "mode": "strict"}}


# ============================================================
# Hybrid Polynomial Test (for reverse mode)
# ============================================================

def polynomial_test_strict(icis):
    """Tight polynomial fit (0.10) + residual autocorrelation < 0.50."""
    n = len(icis)
    if n < MIN_INTERVALS: return None
    log_ici = np.log(np.maximum(icis, 1e-10))
    best_r2, best_alpha = -np.inf, None
    for k in range(1, 31):
        indices = np.arange(k, k + n, dtype=float)
        slope, _, r, _, _ = sp_stats.linregress(np.log(indices), log_ici)
        if r**2 > best_r2: best_r2, best_alpha = r**2, slope
    if not (best_r2 >= 0.95 and best_alpha and 1.5 <= best_alpha <= 6.0):
        return None
    best_err, best_k, best_pred, best_off = np.inf, None, None, 1
    for deg in range(2, min(5, n)):
        for off in range(1, 21):
            indices = np.arange(off, off + n, dtype=float)
            try:
                coeffs = np.polyfit(indices, icis, deg)
                predicted = np.polyval(coeffs, indices)
                rel_err = float(np.mean(np.abs(icis - predicted) / np.maximum(np.abs(icis), 1e-10)))
                if rel_err < best_err:
                    best_err, best_k, best_pred, best_off = rel_err, deg, predicted, off
                if rel_err < 0.05: break
            except: continue
    if best_err > 0.10 or best_pred is None: return None
    residuals = icis - best_pred
    if len(residuals) < 4: return None
    autocorr = float(np.corrcoef(residuals[:-1], residuals[1:])[0, 1])
    if np.isnan(autocorr): autocorr = 0.0
    # Skip autocorrelation check when fit is near-perfect (residuals are just
    # floating-point noise, whose autocorrelation is meaningless)
    if abs(autocorr) > 0.50 and best_err > 0.001:
        return None
    rng = np.random.default_rng(0)
    extreme = 0
    idx_p = np.arange(best_off, best_off + n, dtype=float)
    for _ in range(200):
        perm = rng.permutation(icis)
        try:
            c = np.polyfit(idx_p, perm, best_k)
            p = np.polyval(c, idx_p)
            if float(np.mean(np.abs(perm - p) / np.maximum(np.abs(perm), 1e-10))) <= best_err:
                extreme += 1
        except: continue
    if extreme / 200 >= 0.05: return None
    return {"family": "POLYNOMIAL", "confidence": round(min(1.0, best_r2) * 0.7, 3),
            "details": {"alpha": round(best_alpha, 3), "degree": best_k,
                        "fit_err": round(best_err, 4), "autocorr": round(autocorr, 4), "mode": "strict"}}


# ============================================================
# Full reverse scan (all 6 families with appropriate strictness)
# ============================================================

def _scan_direction_reverse(icis):
    """Reverse: 4 recurrence families + strict prime + strict polynomial."""
    valid = icis[icis > 1e-6]
    n = len(valid)
    if n < MIN_INTERVALS: return []
    cv = float(np.std(valid) / np.mean(valid)) if np.mean(valid) > 0 else 0
    if cv < 0.05: return []
    matches = []
    ratios = valid[1:] / valid[:-1]
    r_bar = float(ratios.mean())
    ratio_cv = float(ratios.std() / max(abs(r_bar), 1e-10))
    for fam in RECURRENCE_FAMILIES:
        delta = abs(r_bar - fam["constant"])
        if delta < fam["tolerance"] and r_bar > 1.10 and ratio_cv < 0.55:
            err, p = fam["recurrence_fn"](valid)
            if err is not None and err < 0.20 and p is not None and p < 0.05:
                # Gate 2.5: Reject geometric backoff
                if _is_geometric_backoff(ratios, fam["constant"]):
                    continue
                g1s = max(0.0, 1.0 - delta / fam["tolerance"])
                g2s = max(0.0, 1.0 - err / 0.20)
                matches.append({"family": fam["name"], "confidence": round((g1s+g2s)/2, 3),
                    "details": {"r_bar": r_bar, "delta": round(delta, 4),
                        "constant": fam["constant_name"], "rec_err": round(err, 4),
                        "p_value": round(p, 4), "equation": fam["equation"]}})
    pr = prime_test_strict(valid)
    if pr: matches.append(pr)
    po = polynomial_test_strict(valid)
    if po: matches.append(po)
    return matches


def reverse_icis(timestamps):
    """Reverse the ICI sequence, return new timestamps."""
    ts = np.array(sorted(timestamps), dtype=float)
    icis = np.diff(ts)
    rev = icis[::-1]
    return list(np.concatenate([[0.0], np.cumsum(rev)]))


def classify_flow(timestamps, connection_level=False, min_pkts=MIN_INTERVALS):
    """
    Scan a flow in both forward and reverse ICI order against the 4
    algebraic recurrence families (Fibonacci, Tribonacci, Padovan, Narayana).

    Returns
    -------
    dict with:
        classification : str  (best match family + direction)
        direction      : str  ('FORWARD' | 'REVERSE' | None)
        confidence     : float
        family         : str
        details        : dict
        all_matches    : list of all matches found
    """
    ts = sorted(timestamps)
    if len(ts) < min_pkts + 1:
        return {
            "classification": "INSUFFICIENT_DATA",
            "direction": None,
            "confidence": 0.0,
            "family": None,
            "details": {},
            "all_matches": [],
        }

    icis_fwd = np.diff(ts)
    rev_ts = reverse_icis(ts)
    icis_rev = np.diff(rev_ts)

    # Forward scan: 4 recurrence families with convergence gate
    fwd_matches = _scan_direction_recurrence_only(icis_fwd)

    # Reverse scan: same 4 families on reversed ICIs
    rev_matches = _scan_direction_recurrence_only(icis_rev)

    # Tag direction
    all_matches = []
    for m in fwd_matches:
        m["direction"] = "FORWARD"
        all_matches.append(m)
    for m in rev_matches:
        m["direction"] = "REVERSE"
        m["family"] = "REVERSE_" + m["family"]
        all_matches.append(m)

    if not all_matches:
        return {
            "classification": "BACKGROUND",
            "direction": None,
            "confidence": 1.0,
            "family": None,
            "details": {},
            "all_matches": [],
        }

    # Best match by confidence
    best = max(all_matches, key=lambda m: m["confidence"])

    return {
        "classification": best["family"] + "_BEACON",
        "direction": best["direction"],
        "confidence": best["confidence"],
        "family": best["family"],
        "details": best["details"],
        "all_matches": all_matches,
    }
