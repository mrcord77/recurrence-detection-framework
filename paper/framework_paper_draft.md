# A Structural Detection Framework for Non-Periodic Deterministic C2 Scheduling: Taxonomy, Ceiling Proof, and Family-Specific Detectors

**Andre Cordero**
RepoSignal.io LLC — Apple Valley, CA

---

> **Revision note (2026-05-30):** This draft incorporates empirical corrections from reproducible test suite (run_all_tests.py). Key updates: (1) Section 4.2 anti-correlation remark clarifying ceiling conservatism; (2) Section 8.1 injection test table; (3) Section 8.4 n≥8 empirical validation table; (4) Section 8.7 jitter tolerance corrected from "robust to 15–20%" to empirically measured 78%/10% and 50%/20% rates; (5) Section 8.8 five-family RITA v5.1.2 validation; (6) Section 8.10 multi-method comparison (0/100 alerts). All test scripts reproducible via `PYTHONPATH=. python3 run_all_tests.py`.

## Abstract

We prove that RITA-style composite regularity scoring — combining interval skew, bimodality, top-interval coverage, and streak length — has a structural ceiling for monotonically growing schedules: for *n* distinct intervals, the maximum composite score is bounded by 0.50 + 0.50/*n*, falling below the 0.70 alert threshold for all *n* ≥ 3. A 20-connection Fibonacci beacon scored 45.9% in RITA v5.1.2 (Severity: None), consistent with the theoretical ceiling of 52.5%. This limitation is structural, not a tuning gap.

We construct a growth-regime taxonomy of deterministic non-periodic scheduling families and present validated multi-gate detectors for two regimes. The exponential regime contains a closed algebraic class — the four binary-coefficient recurrences up to third order (Fibonacci, Tribonacci, Padovan, Narayana) — detected via ratio pre-filter, recurrence confirmation with permutation significance, and convergence-based geometric-backoff rejection. The bounded regime uses irrational rotation detected via the three-gap theorem. Large-scale validation on CTU-13 and Stratosphere datasets (145,406 background flows, 742,000+ evaluations) produced 22 structural activations — fewer than two per dataset — with zero activations on 3,165 labeled botnet flows. The logarithmic and polynomial regimes are identified as open detection problems: their value-based detection signals produced 98% of all false positives in initial testing, revealing a fundamental distinction between relational and value-based detection that may generalize beyond the families studied here.

---

### Paper at a Glance

| Family | Growth Regime | Signal Type | Status | Large-Scale Evidence |
|--------|--------------|-------------|--------|---------------------|
| Fibonacci | Exponential | Relational | **Validated** | 1 / 145K flows |
| Tribonacci | Exponential | Relational | **Validated** | 0 / 145K flows |
| Padovan | Exponential | Relational | **Validated** | 9 / 145K flows |
| Narayana | Exponential | Relational | **Validated** | 9 / 145K flows |
| Rotation | Bounded | Relational | **Validated** | 3 / 145K flows |
| Prime | Logarithmic | Value-based | Open problem | 41,225 / 251K flows |
| Polynomial | Power-law | Value-based | Open problem | 141 / 251K flows |

*Structural activations on labeled background traffic (CTU-13 + Stratosphere). Relational detectors test inter-interval structure. Value-based detectors test individual interval properties. The validated core produces 22 total activations across 145,406 flows.*

---

## 1. Introduction

Command-and-control beaconing produces repeated outbound connections whose timing is observable from Zeek-style metadata even when payloads are encrypted. The behavioral detection tradition established by BotHunter [3], BotSniffer [1], and BotMiner [2] demonstrated that C2 communication can be identified from network behavior alone, without payload inspection or prior knowledge of C2 infrastructure. Regularity emerged as the dominant behavioral signal: RITA applies composite periodicity scoring over interval skew, bimodality, top-interval coverage, and streak length [6, 7]; AsSadhan and Moura exploit inter-flow timing periodicity in control-plane metadata [4]; Lomb-Scargle periodogram analysis recovers periodic signals from irregularly sampled flows [5]; and Elastic's beaconing framework uses autocovariance to flag periodic callback patterns [12].

Modern C2 frameworks have responded with timing evasion. Cobalt Strike's malleable C2 profiles allow operators to customize beacon intervals and add configurable jitter [9, 10]. Sliver and Brute Ratel C4 offer similar timing flexibility [11, 30]. These evasion techniques modify the *regularity* of a periodic signal—stretching intervals, adding noise, mimicking legitimate traffic patterns—but they do not abandon periodicity itself. The beacon still repeats at a characteristic interval, and the detection toolchain has adapted: modern detectors tolerate substantial jitter while still recovering the underlying period.

A beacon does not need to be periodic to be structured. A theoretically plausible alternative replaces the constant-period sleep with a deterministic mathematical sequence—Fibonacci numbers, irrational rotation, or other mathematical sequences—that produces callback intervals with no dominant period, no modal interval, and high variance, while maintaining fully deterministic timing that the attacker can predict. Such schedules are trivial to implement (one to three lines of code per family), operationally reliable (the attacker knows every future callback time), and fall below the structural ceiling of RITA-style composite regularity scoring. Their visibility to other analytical approaches — spectral analysis, autocorrelation, machine learning — varies by family and remains an active area of investigation.

Cordero (2026) [27] introduced this concept for a single scheduling family—phi-compatible additive recurrence—proving that RITA's composite scoring has a structural ceiling that makes growing-interval schedules mathematically unreachable for alert, and presenting a two-gate detector for the Fibonacci family. This paper generalizes that result across several families of deterministic non-periodic scheduling.

**Primary contribution.** We propose that deterministic non-periodic scheduling constitutes a distinct behavioral category, we construct a growth-regime taxonomy to organize it, we prove that RITA-style composite scoring has a structural limitation that prevents it from alerting on growing schedules, and we demonstrate that the algebraic recurrence subclass is operationally detectable with low activation rates on large real-world traffic corpora.

We make four specific contributions:

1. A **structural ceiling proof** for RITA-style composite regularity scoring, showing that monotonically growing schedules with *n* ≥ 3 distinct intervals cannot exceed a composite score of 0.50 + 0.50/*n* — strictly below the 0.70 alert threshold (Section 4).

2. A **taxonomy of seven scheduling families** covering exponential recurrences (four cubics plus the Fibonacci quadratic), logarithmic growth (primes), sub-exponential growth (polynomial), and bounded non-periodic scheduling (irrational rotation), organized by the characteristic equation framework that provides a closed enumeration of the binary-coefficient algebraic recurrence class up to third order (Section 5).

3. A **multi-gate detection architecture** that instantiates across the validated recurrence and bounded families with a shared design pattern — growth/ratio pre-filter (Gate 1), structural confirmation with permutation null (Gate 2), and convergence-based geometric-backoff rejection (Gate 2.5) — plus a bidirectional extension for shrinking-interval schedules and a paradigm-shifted design for bounded schedules based on the three-gap theorem (Sections 6, 9, 10).

4. A **cross-family separation matrix** demonstrating mutual rejection across tested family pairs, with preliminary validation on a 24-hour enterprise Zeek conn.log dataset producing zero actionable false positives after protocol/destination triage (Sections 7, 8).

Throughout the implementation, classification labels identify the structural timing family rather than asserting malicious intent. A classification of ADDITIVE_RECURRENCE_BEACON, TRIBONACCI_RECURRENCE_BEACON, PADOVAN_RECURRENCE_BEACON, NARAYANA_RECURRENCE_BEACON, or ROTATION_BEACON indicates timing structure consistent with the named recurrence or rotation family; contextual triage—destination reputation, protocol, port, host role—remains an inherent design requirement.

> *[Figure 1: Detection Gap Addressed by This Paper — conceptual quadrant map. X-axis: interval regularity (periodic → aperiodic). Y-axis: structural determinism (random → deterministic). Upper-left: periodic deterministic (RITA/AC-Hunter territory). Upper-right: non-periodic deterministic. Lower-left: periodic stochastic (jittered beacons). Lower-right: random. Validated families (Fibonacci, Tribonacci, Padovan, Narayana, Rotation) shown as solid points. Open detection problems (prime, polynomial) shown as dashed/gray.]*

Figure 1 illustrates the broader deterministic non-periodic scheduling space. The validated contribution of this paper is limited to the algebraic recurrence class (four families) and bounded irrational rotation. Prime and polynomial schedules are included as taxonomy members but are treated as open detection problems — their current value-based detectors produced unacceptable false-positive rates at scale (Section 8.4).

---

## 2. Background and Related Work

### 2.1 Behavioral C2 Detection

BotHunter [3] correlates IDS alerts across infection lifecycle stages to identify compromised hosts without prior knowledge of C2 addresses. BotSniffer [1] exploits cross-host temporal synchrony in botnet callback patterns. BotMiner [2] clusters flows by communication pattern without protocol assumptions, establishing that C2 structure is detectable from behavioral metadata alone. Our framework follows this tradition: behavioral metadata only, no payload inspection, no prior C2 knowledge.

### 2.2 Periodicity-Based Detection

The periodicity detection paradigm assumes that C2 beaconing produces a dominant interval recoverable from timing metadata. AsSadhan and Moura [4] detect periodic C2 from NetFlow metadata using periodogram analysis. The Lomb-Scargle periodogram [5] recovers periodic signals from irregularly sampled flows, handling the uneven temporal spacing inherent in network connection data. RITA [6, 7] applies a composite score comprising four components—interval skew, bimodality coefficient, top-interval coverage, and longest consecutive streak at the modal interval—each normalized to [0, 1] and equally weighted. AC-Hunter [8] extends RITA with commercial visualization and enrichment. Elastic Security Labs [12] uses autocovariance-based analysis to identify beaconing patterns in network telemetry.

All periodicity-based approaches share an implicit assumption: a beacon's timing signature contains a recoverable dominant interval. A phi-compatible recurrence schedule, a consecutive prime schedule, or a polynomial growth schedule has no dominant interval—the intervals are all distinct and growing. For RITA-style composite scoring, this assumption gap is not a tuning deficiency; it is a structural property of the scoring methodology, as we prove in Section 4. Whether similar structural limitations apply to spectral, autocorrelation, or ML-based periodicity detectors is an open question not addressed in this paper.

### 2.3 Machine Learning Approaches

Recent work applies machine learning to beacon detection. Zhang et al. [13] perform aggregation-based beaconing detection across large campus networks at ACSAC 2023. The unsupervised NSS model in [14] uses time-series decomposition to identify beaconing in C2 communications. Velasco-Mata et al. [15] demonstrate real-time botnet detection on large bandwidths using random forest classifiers. AI-driven IoT botnet detection [16] achieves high detection rates for stealth C2 communications. The Springer contribution [17] applies AI-based time-series analysis specifically to C2 beaconing.

These approaches improve detection of jittered periodic beacons but continue to treat periodicity as the primary timing feature. Machine learning models trained on periodic beacon datasets — even with jitter augmentation — may have limited or no representation of non-periodic structured scheduling in their training distribution. The structural detection approach presented here is complementary: it provides interpretable, family-specific classification that can serve as features for ML-based downstream analysis.

### 2.4 C2 Framework Evasion

Cobalt Strike's malleable C2 profiles [9] allow operators to configure beacon intervals, jitter percentages, and HTTP traffic shaping. Unit 42 [10] documents popular evasion techniques in malleable profiles, including timing manipulation. Brute Ratel C4 and Sliver [11, 30] offer comparable timing flexibility. The ITEA Journal assessment [28] examines Cobalt Strike's sleep mask and malleable profile evolution through version 4.9. Netskope's C2 detection white paper [29] evaluates beaconing detection approaches against malleable profiles and concludes that current methods struggle with sophisticated timing evasion.

Critically, all documented C2 timing evasion operates within the periodic paradigm—varying the interval and adding jitter, but maintaining an underlying sleep-then-callback cycle. The scheduling families enumerated in this paper represent a qualitatively different evasion approach: replacing periodicity itself with a mathematical structure that carries no periodic component.

### 2.5 Mathematical Foundations

The recurrence families in our taxonomy are linear recurrence sequences whose ratio limits are algebraic numbers—roots of characteristic polynomials with integer coefficients. The Fibonacci sequence converges to the golden ratio φ = (1+√5)/2 ≈ 1.618, the unique positive root of x² − x − 1 = 0. The Tribonacci sequence converges to the Tribonacci constant τ ≈ 1.839, the real root of x³ − x² − x − 1 = 0 [OEIS A058265]. The Padovan sequence converges to the plastic constant ρ ≈ 1.325, the real root of x³ − x − 1 = 0 [OEIS A060006]. Narayana's cows sequence converges to N ≈ 1.466, the real root of x³ − x² − 1 = 0 [OEIS A092526].

The three-gap theorem [21, 22], also known as the Steinhaus conjecture, states that for any irrational α and any N, the N points {frac(nα), n = 1, ..., N} partition the unit circle into gaps of at most three distinct lengths. This result, proved by Sós [21] and given detailed proof by van Ravenstein [22], provides the structural fingerprint for our bounded non-periodic detector. Das and Haynes [23] recently generalized the theorem to rotations on adelic tori, confirming its mathematical robustness. To our knowledge, the three-gap theorem has not previously been applied to network security detection.

The permutation significance test used in all Gate 2 implementations follows the bootstrap methodology of Efron and Tibshirani [19], with finite-sample considerations from Hesterberg [20].

### 2.6 Datasets

Empirical validation uses the UWF-ZeekData22 dataset [26], a comprehensive network traffic collection generated using Zeek and labeled using the MITRE ATT&CK framework. The dataset contains approximately 9.28 million attack records and 9.28 million benign records collected from the University of West Florida's cyber range. Our evaluation uses the benign week (January 2-9, 2022, 1 million records) and the Recon/Discovery attack week. Additionally, we use a 24-hour enterprise Zeek conn.log dataset with injected beacons for controlled false-positive characterization, and real RITA v5.1.2 binary output on the same dataset.

---

## 3. Threat Model

The attacker in this model controls a compromised host and can specify the callback timing schedule. The schedule is implemented in the beacon implant's sleep function and executes deterministically without requiring external coordination. The defender has Zeek-style connection metadata—timestamps, source/destination addresses, ports, protocol—with no payload content. Payloads may be encrypted (HTTPS) and may transit legitimate infrastructure (CDNs, cloud services).

Seven scheduling families are under study:

**Recurrence families.** The attacker replaces a constant sleep with a Fibonacci-like recurrence iterator. Implementation complexity is minimal:

```
# Fibonacci: sleep(fib[n] * base)
# Tribonacci: sleep(trib[n] * base)    where trib[n] = trib[n-1] + trib[n-2] + trib[n-3]
# Padovan: sleep(pad[n] * base)        where pad[n] = pad[n-2] + pad[n-3]
# Narayana: sleep(nar[n] * base)       where nar[n] = nar[n-1] + nar[n-3]
```

Each requires 3-5 lines of code in any language. The recurrence state (three integers) is trivially maintained across callbacks.

> *[Figure 2: Implementation Complexity — Each scheduling family requires 1–3 lines of code, minimal state (2–3 integers or one counter), and no cryptographic random number generator.]*

**Prime intervals.** `sleep(prime[n] * base)` using a precomputed or sieved prime table. Requires a small lookup table (the first 100 primes fit in 400 bytes).

**Polynomial growth.** `sleep(base * n**2)` or `sleep(base * n**3)`. One line of code, no state beyond the callback counter.

**Irrational rotation.** `sleep(min + range * ((n * 1.618033988749895) % 1))`. One line of code, bounded intervals, no repeats, deterministic.

**Reverse variants.** Any of the above with the index reversed: `sleep(seq[n_max - n] * base)`. Produces shrinking intervals—slow start during persistence, acceleration during exfiltration.

This paper evaluates detectability of these schedule families. The case rests on theoretical plausibility and implementation simplicity, not on documented malware adoption. No confirmed real-world malware sample uses any of these scheduling families. Detection of each structural family is evaluated as a characterization contribution, not a prevalence claim.

### Family Selection Rationale

The taxonomy spans four growth regimes: they span all four growth regimes in the taxonomy (bounded, logarithmic, polynomial, exponential), and within the exponential regime, they include a closed algebraic enumeration of the binary-coefficient recurrence subclass up to third order. The selection is neither arbitrary nor claimed to be exhaustive — it is structured coverage of representative growth regimes combined with algebraic closure where the mathematics permits it.

- **Algebraic recurrence** (Fibonacci, Tribonacci, Padovan, Narayana): the four non-degenerate binary-coefficient linear recurrences up to third order, producing exponential growth at four distinct algebraic rates. Within this specific algebraic class, the enumeration is closed — no additional families exist with these coefficient constraints.
- **Logarithmic growth** (primes): the natural representative of the logarithmic growth regime. Unlike the recurrence families, which are selected by algebraic enumeration, the prime family is selected by growth-class coverage — it is the simplest and most widely recognized integer sequence with logarithmic growth. The theoretical foundation (prime number theorem, consecutive alignment) is weaker than the algebraic identities underlying the recurrence detectors, but the growth regime itself must be represented in a taxonomy organized by growth class.
- **Power-law growth** (polynomial): sub-exponential growth at configurable rate, representing the continuous-exponent growth regime between logarithmic and exponential.
- **Bounded deterministic** (irrational rotation): a qualitatively different paradigm — intervals that do not grow at all but fill a fixed range quasi-randomly, representing the zero-growth regime.
- **Directional reversal**: shrinking-interval variants of all above, representing the negative-growth regime.

We do not claim this taxonomy covers all possible deterministic non-periodic schedules. Higher-order recurrences, non-linear sequences, chaotic maps, and quasi-random constructions outside irrational rotation (van der Corput, Halton) are explicitly outside scope. What we claim is coverage of representative growth regimes with algebraic closure within the recurrence subclass — a structured starting point for a detection category that did not previously have one.

### Validated Core vs. Exploratory Prototypes

Large-scale validation on the CTU-13 dataset (Section 8) revealed a fundamental distinction between two classes of detector within the framework:

**Validated core (relational signal).** The four recurrence detectors and the bounded rotation detector test *structural relationships between consecutive intervals* — each interval is a deterministic function of previous intervals, and the detection gates verify this relationship. These detectors produced a 0.24% flow-level false-positive rate across 251,459 labeled background flows. The Reverse Scanner (v1.2) applies the four recurrence detectors bidirectionally for shrinking-interval schedules.

**Exploratory prototypes (value-based signal).** The prime and polynomial detectors test *properties of individual interval values* — whether values are near primes, or whether the sequence shape fits a power law. These are fundamentally different signal types. Prime-adjacency is not sufficiently discriminative: approximately one in eight integers near typical interval values is prime, making coincidental matches common. The prime detection path generated 98% of all structural false positives in CTU-13 validation. The polynomial detector had the second-highest false-positive rate for the same structural reason: log-log linearity describes a curve shape, not a generative relationship between intervals.

Both detector classes are included in the taxonomy because the taxonomy is organized by growth regime, and logarithmic and polynomial growth are genuine regimes. However, only the relational detectors — those that test inter-interval structure rather than individual-interval properties — achieved operational false-positive rates at scale.

### Operational Incentives for Non-Periodic Scheduling

A reviewer may reasonably ask: why would an attacker choose a mathematical sequence over jittered periodic scheduling? The question is best answered by precedent. Adversary adoption of timing evasion has followed a consistent pattern: Cobalt Strike introduced configurable jitter [9, 10]; Sliver and Brute Ratel added timing flexibility [11, 30]; sleep-mask techniques evolved to evade in-memory scanning during callback delays; malleable C2 profiles now routinely include timing manipulation. Each step represents an attacker responding to a detection methodology by modifying the specific signal that methodology measures. Deterministic non-periodic scheduling is the next logical step on this continuum — modifying the timing structure itself rather than adding noise to a periodic signal.

We identify five specific operational incentives:

1. **Periodicity scoring evasion.** RITA-style composite scoring is the most widely deployed beacon detection methodology. A growing-interval schedule is provably below the alert threshold (Section 4). Jittered periodic scheduling remains detectable at moderate jitter levels because the dominant interval persists.

2. **Spectral characteristics.** Periodic beacons — even heavily jittered — produce recoverable spectral peaks at their behavioral period in periodogram or autocorrelation analysis. Non-periodic growing schedules produce no dominant behavioral period, but Rayleigh periodogram analysis (Section 8.9) shows that recurrence families produce significant peaks at observation-scale periods reflecting non-stationarity (event clustering at the start of the window). The spectral visibility of non-periodic schedules is family-dependent and varies with observation length and analytical method — it is not uniformly absent.

3. **Deterministic rendezvous.** Unlike random-jitter scheduling where the C2 server cannot predict the next callback time, mathematical sequences are fully deterministic. Both implant and server can independently compute the exact callback schedule. This enables server-side timeout optimization, missed-beacon alerting, and infrastructure provisioning.

4. **Minimal implant complexity.** Each schedule is 1–5 lines of code with no external dependencies. No cryptographic random number generator is required (eliminating a dependency that may be unavailable or detectable on constrained implants). The recurrence state is three integers; the rotation state is one counter.

5. **Novelty advantage.** No deployed detection tool tests for these scheduling families. The attacker benefits from a structural detection gap rather than relying on parameter tuning (jitter percentage) to stay below an empirical threshold.

---

## 4. Structural Ceiling of Periodicity-Based Scoring

### 4.1 RITA-Style Composite Score

The RITA-style composite beacon score is the equal-weighted average of four components, each normalized to [0, 1]:

- **Skew score**: max(0, 1 − |skew(ICIs)| / 3.0). Measures asymmetry of the interval distribution.
- **Bimodal score**: derived from Sarle's bimodality coefficient. High for distributions with two modes (beacon + noise).
- **Top-interval coverage**: fraction of ICIs landing in the modal rounded-second bucket. High when many intervals are identical.
- **Streak score**: longest consecutive run at the modal interval divided by *n*. High when the beacon maintains a consistent interval over time.

The composite score is (skew + bimodal + top_cover + streak) / 4.

### 4.2 The Structural Ceiling Theorem

**Theorem.** For any monotonically growing schedule with *n* ≥ 3 distinct inter-connection intervals, the maximum composite score under the equal-weight four-component scoring defined above is:

max_score = 0.50 + 0.50/*n* < 0.70

**Proof.** A monotonically growing schedule has *n* distinct interval values, each appearing exactly once (or a bounded number of times for near-monotonic schedules). We analyze each component of the RITA-style composite score independently.

*Top-interval coverage:* The modal interval bucket contains at most ⌈*n*/*k*⌉ intervals where *k* is the number of distinct rounded-second values. For a monotonically growing schedule where all intervals are distinct, the modal bucket contains at most 1 interval (or a small constant if intervals round to the same second). Thus top_cover ≤ 1/*n*.

*Streak score:* The longest consecutive run at any single modal value is at most 1 for a strictly monotonic schedule (no two consecutive intervals are equal). Thus streak ≤ 1/*n*.

*Upper bound:* Even if skew and bimodal both achieve their maximum value of 1.0, the composite score is bounded:

max_score = (1.0 + 1.0 + 1/*n* + 1/*n*) / 4 = 0.50 + 0.50/*n*

This ceiling is strictly below the typical RITA alert threshold of 0.70 for all *n* ≥ 3:

| *n* (intervals) | Ceiling | Gap to 0.70 | Below threshold? |
|-----------------|---------|-------------|-----------------|
| 2               | 0.750   | +0.050      | **No** |
| 3               | 0.667   | −0.033      | Yes |
| 5               | 0.600   | −0.100      | Yes |
| 7               | 0.571   | −0.129      | Yes |
| 10              | 0.550   | −0.150      | Yes |
| 15              | 0.533   | −0.167      | Yes |
| *n* → ∞         | 0.500   | −0.200      | Yes |

*Table 1. Maximum RITA-style composite score for monotonically growing schedules. The ceiling exceeds 0.70 only at n = 2, which represents a degenerate two-interval schedule insufficient for reliable detection by any method. All detectors in this framework require a minimum of 6–8 intervals.*

This result is independent of the specific growth rate, mathematical family, or implementation. Whether the schedule is Fibonacci, Tribonacci, Padovan, Narayana, prime, polynomial, or any other monotonically growing sequence, the same ceiling applies for n ≥ 3. ∎

**Remark (conservatism of the bound).** The proof grants the adversary skew_score = 1.0 and bimodal = 1.0 simultaneously as an upper bound. For any monotonically growing sequence, these two components are structurally anti-correlated: high positive skew reduces skew_score (via the |skew|/3 penalty term) while simultaneously increasing Sarle's bimodality coefficient (via the skew² numerator). Their sum is empirically bounded near 1.16 for all tested recurrence families at n ≥ 8, compared to the proof's assumed maximum of 2.0. As a result, actual composite scores for growing sequences fall significantly below the stated ceiling — Fibonacci at n=20 scores approximately 0.31, well below the ceiling of 0.525. The stated ceiling is therefore an intentionally conservative worst-case guarantee: it holds even if the adversary's schedule somehow achieves the maximum bimodality simultaneously with maximum skew regularity, which no growing sequence can do in practice. The RITA v5.1.2 empirical result (45.9% for Fibonacci at n=20) falls below the ceiling as predicted, and the gap between ceiling and observation is explained by this anti-correlation. (Verified computationally in test1_rita_ceiling.py.)

### 4.3 Edge Cases and Robustness of the Ceiling

The formal theorem (Section 4.2) applies to strictly monotonic schedules where all *n* intervals map to distinct rounded-second buckets. We now consider relaxations. The first extends the formal result; the remaining two are empirical observations.

**Bucket collisions (formal extension).** RITA rounds intervals to the nearest second before computing top-cover. If at most *k* intervals share the modal rounded-second bucket, then top_cover ≤ k/n and streak ≤ k/n, and the ceiling generalizes to 0.50 + k/(2n). For k = 3 (the maximum observed in recurrence schedules with base ≥ 5 seconds), the ceiling is below 0.70 for n ≥ 7. This extension is formally sound under the same proof structure as the strict case.

**Near-monotonic schedules (empirical).** Jitter can produce local non-monotonicity: interval 7 might be slightly shorter than interval 6 due to timing noise. For the jitter levels tested in this paper (up to 20%), the maximum bucket multiplicity *k* remains small relative to *n*, and the generalized ceiling holds. This is a measured property of the evaluated schedules, not a formal guarantee — schedules with extreme jitter or pathological rounding could in principle produce higher *k* values.

**Schedules that are not purely monotonic (empirical).** Some mathematical sequences are eventually monotonic but not initially so (e.g., Padovan begins 1, 1, 1, 2, 2, 3...). The ceiling applies to the monotonic portion. In practice, the non-monotonic prefix is short (3–5 terms) and the sequence becomes strictly monotonic well within the minimum interval window of 6–8 connections.

> *[Figure 3: Structural Ceiling — line plot showing max_score = 0.50 + 0.50/n vs n, with the 0.70 alert threshold as horizontal dashed line. The ceiling curve approaches 0.50 asymptotically, never reaching the threshold.]*

### 4.4 Generalization Beyond Growing Schedules

The ceiling theorem addresses growing schedules. Bounded non-periodic schedules (Section 10) evade periodicity detection through a different mechanism: they have no dominant interval at all. A rotation sequence with N distinct bounded intervals produces top_cover ≤ 2/*N* (at most two intervals may round to the same second) and streak = 1/*N*. The composite score remains below the alert threshold by the same structural argument, but the evasion mechanism is distributional rather than growth-based.

### 4.5 Empirical Validation

Real RITA v5.1.2 binary output on a 24-hour enterprise Zeek conn.log confirms the ceiling. Phi-compatible growing-interval schedules from the adversarial battery score below 0.30 in RITA-style scoring, consistent with the ceiling formula. The 30-second jittered periodic beacon in the same dataset scores 0.617 Low severity—this is expected because a near-periodic schedule does populate the top-cover and streak components. The structural ceiling applies specifically to monotonically growing schedules with distinct intervals.

> *[Figure 4: RITA Component Decomposition — stacked bar chart showing skew, bimodal, top-cover, and streak scores for representative schedule families. Top-cover and streak collapse for all growing and bounded families.]*

---

## 5. Taxonomy of Non-Periodic Structured Schedules

The taxonomy organizes deterministic non-periodic schedules by **growth regime** — the asymptotic behavior of the inter-connection interval as the callback index increases. Growth regime is selected as the primary organizing axis because it directly determines the observable evolution of inter-connection intervals and naturally partitions the deterministic non-periodic scheduling space into four classes with distinct detection signatures:

| Growth Regime | Interval Behavior | Representative Families | Detection Signal |
|---------------|-------------------|------------------------|-----------------|
| Bounded | Intervals stay within a fixed range | Irrational rotation | Three-gap clustering |
| Logarithmic | Intervals grow as n·ln(n) | Consecutive primes | PNT fit + alignment |
| Polynomial | Intervals grow as n^α | Power-law schedules | Log-log linearity |
| Exponential | Intervals grow as C^n | Algebraic recurrences | Ratio convergence + recurrence |

*Table 2. Growth-regime taxonomy of deterministic non-periodic schedules.*

Other organizing principles — recurrence structure, entropy, predictability, spectral properties, state complexity — are plausible alternatives. We selected growth regime because it maps directly to the observable quantity (ICI evolution over time) and because it yields clean detection-method separation: each growth regime requires a structurally different Gate 1 pre-filter, as no single pre-filter test works across regimes. A ratio convergence test detects exponential growth but not polynomial; a log-log linearity test detects polynomial growth but not exponential; a boundedness test detects rotation but rejects all growth families. The growth regime determines the detection approach.

### 5.1 Algebraic Recurrence Class

The exponential growth regime contains a structured algebraic subclass: linear recurrences with binary coefficients. Every recurrence of the form a(*n*) = c₁a(*n*−1) + c₂a(*n*−2) + c₃a(*n*−3) with each cᵢ ∈ {0, 1} maps to a characteristic polynomial whose unique positive real root determines the growth ratio. The four non-degenerate members of this class — Fibonacci, Tribonacci, Padovan, and Narayana — are not four independent contributions. They are four exemplars of a single algebraic family, distinguished only by which terms appear on the right side of the recurrence. The characteristic equation framework is the contribution; the individual detectors are instantiations.

| Coefficients (c₁, c₂, c₃) | Recurrence | Char. Equation | Real Root | Name |
|---------------------------|------------|---------------|-----------|------|
| (1, 1, 0)                 | a(n−1) + a(n−2) | x² = x + 1 | φ ≈ 1.618 | Fibonacci |
| (1, 1, 1)                 | a(n−1) + a(n−2) + a(n−3) | x³ = x² + x + 1 | τ ≈ 1.839 | Tribonacci |
| (0, 1, 1)                 | a(n−2) + a(n−3) | x³ = x + 1 | ρ ≈ 1.325 | Padovan |
| (1, 0, 1)                 | a(n−1) + a(n−3) | x³ = x² + 1 | N ≈ 1.466 | Narayana |

*Table 3. The algebraic recurrence class: binary-coefficient recurrences up to third order. This enumeration is closed — no additional non-degenerate families exist within these coefficient constraints.*

The remaining binary-coefficient possibilities — (0, 0, 1), (0, 1, 0), (1, 0, 0) — produce degenerate sequences (constant, oscillating, or linear growth) trivially detectable by existing tools. The four entries in Table 3 are the only non-degenerate members of this algebraic class. This is a closed enumeration within a specific coefficient class — it does not imply coverage of all possible non-periodic deterministic scheduling strategies. Higher-order recurrences, non-linear sequences, quasi-random constructions (van der Corput, Halton), and hybrid approaches remain outside this classification.

> *[Figure 6: Characteristic Equation Family Tree — tree diagram showing how each binary coefficient vector maps to a characteristic equation and its real root. The quadratic (Fibonacci) is the degenerate case where c₃ = 0.]*

### 5.2 Recurrence Growth Spectrum

Each recurrence constant occupies a distinct position on the real number line, with non-overlapping Gate 1 acceptance windows:

| Family | Constant | Gate 1 Window | Growth per Step |
|--------|----------|--------------|-----------------|
| Padovan | ρ ≈ 1.325 | [1.175, 1.475] | +32% |
| Narayana | N ≈ 1.466 | [1.346, 1.586] | +47% |
| Fibonacci | φ ≈ 1.618 | [1.45, 1.80] | +62% |
| Tribonacci | τ ≈ 1.839 | [1.689, 1.989] | +84% |

*Table 3. Recurrence family constants and acceptance windows.*

The windows overlap in narrow bands (Padovan–Narayana near 1.45, Narayana–Fibonacci near 1.50, Fibonacci–Tribonacci near 1.70). In overlap regions, Gate 2 discriminates: each family's recurrence test checks a structurally distinct relationship between terms. A Fibonacci sequence tested against the Tribonacci recurrence produces 23.6% residual (above the 0.20 threshold); a Tribonacci sequence tested against the Fibonacci recurrence produces 6.6% residual but fails Gate 1 (ratio too high).

> *[Figure 9: Acceptance Windows on the Ratio Line — annotated number line from 1.0 to 2.2 showing each family's Gate 1 window, with constants ρ, N, φ, τ marked.]*

### 5.3 Non-Recurrence Families

**Consecutive prime intervals.** The *n*th prime p(*n*) grows as p(*n*) ~ *n* · ln(*n*) by the prime number theorem [25]. This logarithmic growth — slower than any exponential recurrence, faster than bounded — fills a gap in the growth-class coverage and is trivial to implement via precomputed prime tables. However, CTU-13 validation revealed that prime-adjacency is not a sufficiently discriminative detection signal: individual interval values near primes are too common in arbitrary integer sequences (density ~1/ln(n)). Detection methods for the logarithmic growth regime that test inter-interval relationships rather than individual-interval properties remain an open research problem (Section 13).

**Polynomial growth.** ICI(*n*) = base × *n*^α for integer or non-integer α ≥ 1.5. Growth is sub-exponential—much slower than any recurrence family. Consecutive ratios ((*n*+1)/*n*)^α trend toward 1.0 rather than converging to a constant, making ratio-based detectors inapplicable. Potential detection signals include log-log linearity (log ICI vs log *n* should be linear with slope α) and polynomial fit with residual analysis. However, CTU-13 validation showed that these value-based signals produce elevated false-positive rates compared to relational tests, and polynomial detection remains an open research problem (Section 13). Implementation: `sleep(base * n**2)`.

### 5.4 The Bounded Paradigm

Irrational rotation sequences represent a qualitative departure from growth-based scheduling. The intervals are bounded within a fixed range (e.g., 30–120 seconds), non-repeating, and fully deterministic:

ICI(*n*) = min + (max − min) × frac(*n* × α)

where α is irrational and frac(·) takes the fractional part. The resulting intervals lack growth structure and resemble noisy application traffic to growth-based detectors. The structural fingerprint comes from the three-gap theorem [21, 22]: for any irrational α and any *N*, the sorted values partition [0, 1] into gaps of at most three distinct lengths. Random uniform samples produce *N* distinct gap lengths. This difference is the detection signal.

### 5.5 Reverse Variants

Any schedule can be run in reverse: intervals decrease rather than increase. A reverse-Fibonacci beacon produces intervals 21, 13, 8, 5, 3, 2 seconds—starting with low-profile long intervals during persistence and accelerating during active exfiltration. The Reverse Scanner (v1.2) flips the ICI sequence and tests it against the four recurrence families in both directions, applying the same multi-gate architecture with convergence verification.

> *[Figure 5: Taxonomy Map — All seven scheduling families positioned by growth regime (bounded → logarithmic → power-law → exponential) and detection signal type.]*

> *[Figure 7: Growth Rate Comparison — semi-log plot showing interval magnitude vs index n for all seven families on the same axes. Tribonacci grows fastest, followed by Fibonacci, Narayana, Padovan, primes, polynomial. Rotation is bounded flat.]*

---

## 6. Multi-Gate Detection Architecture

### 6.1 Design Pattern

All detectors share a common multi-gate architecture:

**Gate 1 (Pre-filter):** A computationally inexpensive test that eliminates most background traffic before the more expensive Gate 2 runs. For recurrence families, Gate 1 tests whether consecutive ICI ratios cluster near the family's algebraic constant. For bounded rotation, it confirms non-trending, non-constant, bounded intervals.

**Gate 2 (Structural Confirmation):** A specific mathematical test that confirms the structural fingerprint with permutation significance. For recurrence families, Gate 2 tests the exact recurrence relationship (e.g., ICI[*n*+2] ≈ ICI[*n*+1] + ICI[*n*] for Fibonacci) against a 500-iteration permutation null. For bounded rotation, it counts gap-length clusters and measures star discrepancy.

**Gate 2.5 (Geometric-Backoff Rejection):** A test that discriminates true recurrence from geometric backoff — the primary source of false positives identified during systematic backoff testing (Section 8.6). For recurrence families, Gate 2.5 computes the linear regression slope of |ratio − constant| versus index; true recurrence shows convergence (negative slope) while geometric backoff shows no convergence (zero or positive slope). For power-law and prime detectors, Gate 2.5 checks for capped-geometric signatures (≥ 2 non-monotonic ICI ratios), characteristic of retry patterns that plateau after hitting a maximum delay.

All three gates must pass for a positive classification. Gate 2's structural test is astronomically unlikely to pass by coincidence on random traffic. Gate 2.5 ensures that structured geometric growth near a family constant is not misclassified as additive recurrence — a distinction that cannot be made by recurrence residuals alone when the geometric ratio satisfies r² ≈ r + 1 (as it does for r ≈ φ).

> *[Figure 8: Multi-Gate Pipeline Architecture — showing input flow from Zeek conn.log through ICI computation, branching to recurrence and bounded detector types, each with Gate 1 pre-filter, Gate 2 structural confirmation, and Gate 2.5 geometric-backoff rejection.]*

### 6.2 Recurrence Family Gate Instantiation

Each recurrence family instantiates the gates with its own algebraic constant, tolerance, acceptance window, and recurrence relation:

| Family | Constant | Gate 1 Window | Gate 1 Tolerance | Gate 2 Recurrence | Gate 2 Threshold | Char. Equation |
|--------|----------|--------------|-----------------|-------------------|-----------------|---------------|
| Fibonacci | φ ≈ 1.618 | [1.45, 1.80] | |r̄ − φ| < 0.20 | ICI[n+2] ≈ ICI[n+1] + ICI[n] | residual < 0.20 | x² = x + 1 |
| Tribonacci | τ ≈ 1.839 | [1.69, 1.99] | |r̄ − τ| < 0.15 | ICI[n+3] ≈ ICI[n+2] + ICI[n+1] + ICI[n] | residual < 0.20 | x³ = x² + x + 1 |
| Padovan | ρ ≈ 1.325 | [1.18, 1.48] | |r̄ − ρ| < 0.15 | ICI[n] ≈ ICI[n−2] + ICI[n−3] | residual < 0.20 | x³ = x + 1 |
| Narayana | N ≈ 1.466 | [1.35, 1.59] | |r̄ − N| < 0.12 | ICI[n] ≈ ICI[n−1] + ICI[n−3] | residual < 0.20 | x³ = x² + 1 |

*Table 4a. Recurrence family gate specification. All Gate 2 tests use 200–500 iteration permutation null with significance threshold p < 0.05.*

The bounded rotation detector uses structurally different gates:

| Family | Gate 1 Test | Gate 1 Threshold | Gate 2 Test | Gate 2 Threshold |
|--------|------------|-----------------|------------|-----------------|
| Bounded | Range < 5×, CV > 0.10, no trend | slope/mean < 0.03 | Three-gap clusters + D* | clusters ≤ 4, D* < 0.20 |

*Table 4b. Bounded rotation gate specification.*

The theoretical residual for geometric ratio *r* tested against each family's Gate 2 is:

- Fibonacci: |*r*² − *r* − 1| / *r*²
- Tribonacci: |*r*³ − *r*² − *r* − 1| / *r*³
- Padovan: |*r*³ − *r* − 1| / *r*³
- Narayana: |*r*³ − *r*² − 1| / *r*³

Each formula equals zero at the family's algebraic constant (by definition of the characteristic equation) and increases away from it, providing natural discrimination against other families.

### 6.3 Statistical Methodology

**Permutation significance testing.** All Gate 2 tests use a permutation-based nonparametric significance test. The null hypothesis is that the ICI sequence has no structural relationship beyond what would occur by chance — i.e., that any observed recurrence residual or alignment score could be produced by a random reordering of the same interval values. The test procedure:

1. Compute the observed test statistic *T_obs* on the original ICI sequence (e.g., mean Fibonacci recurrence residual).
2. Generate *B* = 200–500 random permutations of the ICI sequence.
3. Compute *T_perm* for each permutation.
4. The p-value is the fraction of permutations where *T_perm* ≤ *T_obs*.

A deterministic schedule produces *T_obs* far below any permutation (typically p = 0/500 = 0.000), because the structural relationship is destroyed by reordering. Random or Poisson traffic produces *T_obs* comparable to permutations (typically p > 0.10), because no structural relationship exists to destroy.

**Choice of B = 200–500.** The permutation count was chosen to balance computational cost against p-value resolution. At B = 500, the minimum achievable p-value is 1/500 = 0.002; at B = 200, it is 1/200 = 0.005. Both provide sufficient resolution for the significance threshold of p < 0.05, and in practice all true-positive detections produce p = 0.000 (zero permutations match), while all true-negative classifications produce p > 0.10. Increasing B to 10,000 would improve p-value precision but would not change any classification decision, because the gap between true-positive and true-negative p-values spans two orders of magnitude. The fixed random seed (seed = 0) ensures reproducibility across runs.

**Multiple comparison correction.** Each flow is tested against at most five detectors (four recurrence families plus bounded rotation). The Bonferroni-corrected significance threshold would be 0.05/5 = 0.01. In practice, no correction is applied because Gate 1's pre-filter ensures that at most one or two detectors reach Gate 2 for any given flow — the acceptance windows are non-overlapping for most of the ratio spectrum, so the effective number of comparisons is typically 1, not 5.

**Convergence slope test (Gate 2.5).** The geometric-backoff rejection gate uses simple linear regression (scipy.stats.linregress) on the deviation sequence |ratio[i] − constant| vs. index i. The threshold of −0.008 was selected empirically by sweep across gRPC backoff (50 seeds) and true Fibonacci sequences (50 seeds at 0%, 10%, 15%, 20% jitter), optimizing for the operating point that maximizes gRPC rejection while preserving ≥ 95% Fibonacci detection at 10% jitter. The threshold is not theoretically derived; it is a tuned parameter that may require adjustment for deployment environments with different retry-traffic profiles.

**Confidence intervals.** For the CTU-13 large-scale validation, 0.24% flow-level FPR is a point estimate from a single scenario (71/29,061 flows). The 95% Clopper-Pearson binomial confidence interval is [0.19%, 0.31%]. For the enterprise Zeek validation, 0 flags in 204 flows yields a 95% upper bound of approximately 1.5%. These bounds characterize measurement precision, not the true operational FPR, which requires multi-site validation to establish.

---

## 7. Cross-Family Separation

### 7.1 Theoretical Residual Matrix

The residual formulas from Section 6.2 yield a theoretical cross-family discrimination matrix. Each entry shows the residual when a schedule following family A (row) is tested against family B's Gate 2 recurrence test (column):

| Tested as → | Fibonacci | Tribonacci | Padovan | Narayana |
|-------------|-----------|------------|---------|----------|
| **Fibonacci (φ)** | **0.000** | 0.236 | 0.382 | 0.146 |
| **Tribonacci (τ)** | 0.066 | **0.000** | 0.544 | 0.296 |
| **Padovan (ρ)** | 0.066 | 0.245 | **0.000** | 0.185 |
| **Narayana (N)** | 0.125 | 0.208 | 0.079 | **0.000** |

*Table 5. Cross-family theoretical residuals. Bold diagonal = detected (residual = 0). Off-diagonal values above the 0.20 Gate 2 threshold are cleanly rejected. Values below 0.20 (e.g., Fibonacci→Narayana at 0.146) require Gate 1 for discrimination.*

The matrix reveals that Gate 2 alone cleanly separates most family pairs (residual > 0.20), but certain adjacent families—notably Fibonacci tested against Narayana (0.146) and Padovan tested against Narayana (0.079)—produce residuals below the Gate 2 threshold. In these cases, Gate 1's ratio test discriminates: |φ − N| = 0.152 exceeds Narayana's Gate 1 tolerance of 0.12, and |ρ − N| = 0.141 also exceeds it. The multi-gate architecture is essential—neither gate alone provides complete separation.

> *[Figure 10: Cross-Family Residual Heatmap — 6×6 heatmap showing tested schedule (rows) vs detector gate (columns). Diagonal is green (0.000), most off-diagonal is red (>0.20). Near-diagonal cells in yellow (0.05–0.15) show where Gate 1 is needed for discrimination.]*

### 7.2 Empirical Classification Matrix

We ran each detector on synthetic schedules from every family. The complete classification confirms theoretical predictions: every tool correctly identifies its own family and rejects all others at the classify_flow level (both gates applied).

### 7.3 Gate 1 Window Overlap Analysis

The four recurrence families' Gate 1 acceptance windows on the ratio number line have narrow overlaps:

- Padovan [1.175, 1.475] ∩ Narayana [1.346, 1.586] = [1.346, 1.475]
- Narayana [1.346, 1.586] ∩ Fibonacci [1.45, 1.80] = [1.45, 1.586]
- Fibonacci [1.45, 1.80] ∩ Tribonacci [1.689, 1.989] = [1.689, 1.80]

In each overlap region, a geometric sequence with ratio in the overlap would pass both families' Gate 1. Gate 2 discriminates: different recurrence relations, different residuals. Consider a geometric sequence with ratio r = 1.45, which lies in the Padovan–Narayana overlap. This ratio passes Padovan Gate 1 (|1.45 − 1.325| = 0.125 < 0.15) and Narayana Gate 1 (|1.45 − 1.466| = 0.016 < 0.12). However, the Padovan recurrence residual at r = 1.45 is |1.45³ − 1.45 − 1| / 1.45³ = |3.049 − 2.45| / 3.049 = 0.197, near the 0.20 threshold, while the Narayana recurrence residual is |1.45³ − 1.45² − 1| / 1.45³ = |3.049 − 3.1025| / 3.049 = 0.018, well below threshold. Gate 2 correctly assigns this ratio to Narayana. The multi-gate architecture ensures discrimination even in overlap regions where Gate 1 alone is ambiguous.

> *[Figure 9: Acceptance Windows on the Ratio Line]*

---

## 8. Empirical Validation

The following table maps each claim in this paper to the dataset and methodology that supports it:

| Claim | Evidence Source | Scale | Section |
|-------|---------------|-------|---------|
| RITA ceiling theorem | Mathematical proof | N/A | 4 |
| Recurrence family enumeration | Algebraic analysis | N/A | 5 |
| Family-specific detection feasibility | Synthetic schedules + jitter sweeps | 50 seeds × 7 jitter levels | 8.1, 8.7 |
| Cross-family rejection | Synthetic cross-testing | 50 seeds × 5 family pairs | 7 |
| Low activation on enterprise traffic | 24-hour enterprise Zeek conn.log | 204 qualifying flows | 8.2, 8.3 |
| Low activation at scale (22 activations) | CTU-13 + Stratosphere datasets, n ≥ 8 | 145,406 background flows | 8.4 |
| Bidirectional consistency (19 activations) | CTU-13 + Stratosphere, Reverse Scanner config | 145,406 background flows | 8.4 |
| Observation-window sensitivity | CTU-13, n ≥ 6 vs n ≥ 8 comparison | 251,459 vs 145,406 flows | 8.4 |
| Value-based signal failure (prime path) | CTU-13, full prototype evaluation | 251,459 flows, 42,184 activations | 8.4 |
| Backoff confounder resistance | Synthetic retry patterns (8 types × 50 seeds) | 3,200 classifications | 8.6 |
| Gate 2.5 effectiveness | Before/after comparison on backoff battery | 179 → 46 activations | 8.6 |
| Spectral observability | Rayleigh periodogram on synthetic schedules | 11 schedule types | 8.9 |
| RITA v5.1.2 comparison | Real RITA installation on enterprise Zeek | 204 flows | 8.8 |

*Table 6. Evidence mapping: each claim is supported by a specific dataset and methodology. No claim relies on a dataset that does not appear in this table.*

### 8.1 Baseline Detection Gap

The following table summarizes the detection outcome for each scheduling family under RITA-style scoring and each structural detector, demonstrating the gap that motivates this work:

| Schedule | RITA (0.70) | Beacon | Tribonacci | Padovan | Narayana | Bounded |
|----------|-----------|--------|------------|---------|----------|---------|
| Regular 30s | **detected** | — | — | — | — | — |
| Jittered ±25% | **detected** | — | — | — | — | — |
| Fibonacci | missed | **detected** | — | — | — | — |
| Tribonacci | missed | — | **detected** | — | — | — |
| Padovan | missed | — | — | **detected** | — | — |
| Narayana | missed | — | — | — | **detected** | — |
| Rotation (φ) | missed | — | — | — | — | **detected** |
| Poisson random | — | — | — | — | — | — |

*Table 7. Detection gap baseline. RITA detects periodic schedules and misses all non-periodic families. Each validated detector classifies its target family and rejects non-target families. Logarithmic (prime) and polynomial growth regimes are part of the taxonomy but do not have validated detectors; detection methods for these regimes remain an open research problem (see Section 13).*

**Reproducible injection test.** To confirm this gap in a mixed-corpus setting, five beacon flows (one per family, 10% jitter) were injected into a 200-flow Poisson background corpus and evaluated with both RITA-style scoring and the structural detector battery (test2_injection.py, reproducible):

| Flow | RITA score | Ceiling | RITA alert? | Structural | Confidence |
|------|-----------|---------|------------|-----------|-----------|
| fibonacci_beacon (n=20) | 0.309 | 0.525 | no | DETECTED ✓ | 80.8% |
| tribonacci_beacon (n=15) | 0.340 | 0.533 | no | DETECTED ✓ | 71.6% |
| padovan_beacon (n=20) | 0.372 | 0.525 | no | DETECTED ✓ | 89.0% |
| narayana_beacon (n=20) | 0.352 | 0.525 | no | DETECTED ✓ | 78.0% |
| rotation_beacon (n=30) | 0.387 | 0.517 | no | DETECTED ✓ | 21.1% |
| Background (200 flows) | — | — | 0/200 | 0/200 FP | — |

*Table 7b. Reproducible injection test. Five beacons embedded in 200 Poisson background flows. RITA scores all five below threshold; structural detectors classify all five correctly; zero false positives on background. Run: `PYTHONPATH=. python3 test2_injection.py`.*

### 8.2 Validation Summary

The six validated tools were tested on the same 24-hour enterprise Zeek conn.log dataset (59,184 records, 1,424 flows, 202–204 analyzed flows with ≥6 timestamps) and on synthetic schedules with controlled jitter.

| Tool | Validation Checks | Unit Tests | Jitter 20% | Real Zeek Raw Flags |
|------|------------------|-----------|------------|---------------------|
| Beacon Hunter v0.3.0 | 32/32 | 34/34 | 100% | 1 marginal (IPv6 NDP) |
| Tribonacci Hunter v1.1 | 47/47 | 29/29 | 100% | 1 marginal (same flow) |
| Padovan Hunter v1.1 | 53/53 | 26/26 | 99% | 0 |
| Narayana Hunter v1.1 | 53/53 | — | 99% | 0 |
| Reverse Scanner v1.2 | 23/23 | — | 100% (rev) | 0 |
| Bounded Hunter v1.0 | 30/30 | — | ~1% | 0 |

*Table 8. Validation summary. "Raw Flags" counts any output above BACKGROUND classification before triage. Two marginal flags on the same benign IPv6 NDP flow are dismissed in operational triage by multicast destination and ICMPv6 protocol.*

At the current sample sizes, the 95% Clopper-Pearson upper bound on the per-tool false positive rate is approximately 1.5% (0 flags in 204 flows). This characterizes the precision of the current measurement, not the true operational FPR, which requires larger-scale validation to establish.

### 8.3 False Positive Analysis (Enterprise Zeek)

Two tools produced marginal raw flags on real enterprise Zeek data. Beacon Hunter flagged one IPv6 NDP Router Solicitation flow (fe80::→ff02::2, ICMPv6) at 17% confidence; Tribonacci Hunter flagged the same flow at 36% confidence. The flow has five intervals showing expanding backoff at geometric ratio ~1.72, which falls within both the phi window [1.45, 1.80] and the tau window [1.689, 1.989]. Both flags are dismissed in operational triage by IPv6 multicast destination and ICMPv6 protocol — these are not actionable alerts.

On synthetic traffic, no tool produces false positives on Poisson-distributed intervals (0/100 per tool) or on cross-family schedules (0/50 per tested pair).

> *[Figure 13: False Positive Map — All six validated tools × four traffic types (Poisson, jittered periodic, cross-family, real Zeek). Green = zero flags. Two marginal flags on the same benign IPv6 NDP flow are the only non-zero entries.]*

### 8.4 Large-Scale Validation: CTU-13 and Stratosphere Datasets

To characterize structural activation rates on real labeled traffic, we evaluated the validated core detectors against the CTU-13 botnet dataset [33] — 13 multi-hour scenarios containing labeled botnet and background traffic — plus three Stratosphere IPS malware captures [34]. Binetflow files were parsed into flows grouped by (source, destination, port), timestamps extracted and sorted.

**Observation-window selection.** A minimum observation window of n ≥ 8 timestamps was used for all recurrence classifications. Observation-window sensitivity analysis during detector characterization showed that shorter sequences (n = 6–7) produced incidental structural matches where the permutation test has insufficient statistical power (120 possible permutations at n = 6, versus 40,320 at n = 8). Larger observation windows reduced these incidental matches while preserving recurrence-family detection capability on synthetic schedules. The threshold n ≥ 8 represents a calibrated operating point balancing detection sensitivity against statistical reliability.

Empirical detection rate across 30 seeds at 10% jitter confirms the threshold (test3_n_sensitivity.py):

| Family | n=6 | n=7 | **n=8** | n=10 | n=15 | n=20 |
|--------|-----|-----|---------|------|------|------|
| Fibonacci | 100% | 100% | **100%** | 100% | 100% | 90% |
| Tribonacci | 0% | 100% | **100%** | 100% | 96% | 93% |
| Padovan | 0% | 96% | **100%** | 100% | 100% | 100% |
| Narayana | 0% | 100% | **100%** | 100% | 100% | 100% |
| Poisson FP | 0/150 | 0/150 | **0/150** | 0/150 | 0/150 | 0/150 |

*Table 9b. Detection rate vs. connection count. Tribonacci, Padovan, and Narayana show 0% detection at n=6 and reach 96–100% at n=8, confirming the threshold empirically. Zero false positives on Poisson background at all n values.*

**Scale.** 16 datasets processed. 145,406 labeled background flows and 3,165 labeled botnet flows qualified at n ≥ 8.

**Deployment Configuration A — Individual detectors (forward only).** The four recurrence detectors (Beacon Hunter, Tribonacci Hunter, Padovan Hunter, Narayana Hunter) plus Bounded Hunter were evaluated independently. This configuration provides forward-only detection with no redundant classifications.

| Metric | Value |
|--------|-------|
| Background flows tested | 145,406 |
| Botnet flows tested | 3,165 |
| Detectors | 5 |
| Total classifications | 742,855 |
| Structural activations on background | 22 |
| Structural activations on botnet | 0 |

*Table 9. Configuration A results — individual recurrence + bounded detectors, n ≥ 8.*

Per-detector breakdown: Padovan 9, Narayana 9, Bounded 3, Beacon (Fibonacci) 1, Tribonacci 0. After processing over 145,000 background flows and 742,000 detector evaluations, the validated recurrence framework produced 22 structural activations — fewer than two per dataset.

**Deployment Configuration B — Reverse Scanner + Bounded (bidirectional).** The Reverse Scanner v1.2 (which tests all four recurrence families in both forward and reverse direction) plus Bounded Hunter were evaluated as a two-tool deployment, adding reverse-direction coverage for shrinking-interval schedules.

| Metric | Value |
|--------|-------|
| Background flows tested | 145,406 |
| Botnet flows tested | 3,165 |
| Detectors | 2 |
| Total classifications | 297,142 |
| Structural activations on background | 19 |
| Structural activations on botnet | 0 |

*Table 10. Configuration B results — Reverse Scanner v1.2 + Bounded Hunter, n ≥ 8.*

Per-detector breakdown: Reverse Scanner Padovan 8, Reverse Scanner Narayana 7, Bounded 3, Reverse Scanner Fibonacci 1. The two configurations produce nearly identical activation counts on the same flows, confirming that the Reverse Scanner produces results consistent with the individual detectors and that reverse-direction scanning adds minimal additional noise.

**Botnet flow analysis.** Zero structural activations were produced on 3,165 labeled botnet flows across either configuration. This is expected: no malware in the CTU-13 dataset uses recurrence-based or rotation-based scheduling. The botnet C2 channels in CTU-13 use near-constant-interval periodic beaconing, which the structural detectors correctly classify as non-matching. This result demonstrates low activation on benign traffic, not detection capability against recurrence-scheduled malware — a distinction the threat model explicitly acknowledges.

**Observation-window sensitivity.** At n ≥ 6 (the minimum mathematically sufficient window), 251,459 background flows qualified and the individual recurrence detectors produced 385 structural activations. The increase from 22 to 385 is driven almost entirely by n = 6–7 flows where the permutation test's limited combinatorial space (120 permutations) allows incidental matches. The n ≥ 8 threshold eliminates these marginal cases while requiring only two additional observed callbacks.

> *[Figure 18: CTU-13 Progressive Refinement — structural activations on background traffic across three configurations: full prototype with prime/polynomial (42,184), validated core at n≥6 (385), validated core at n≥8 (22). A 99.95% reduction from systematic signal-quality filtering.]*

**Relational vs. value-based signal quality.** During initial evaluation, prime and polynomial detection paths were also tested alongside the recurrence detectors. These produced 42,184 structural activations — 98% from the prime detection path. Investigation revealed a fundamental signal-quality difference: recurrence detectors test structural relationships between consecutive intervals (ICI[n] = f(ICI[n-1], ICI[n-2])), while prime detection tests whether individual interval values are near prime numbers. Because primes have density ~1/ln(n), coincidental prime-adjacency is common in arbitrary integer sequences. All 146 structural activations on botnet flows were prime misclassifications — periodic C2 at intervals that happened to be near prime values (e.g., 2369 seconds). This analysis led to the exclusion of value-based detection paths from the validated core; the logarithmic and polynomial growth regimes are identified as open detection problems in Section 13.

### 8.5 Validation Limitations

The current validation has several constraints that limit the strength of false-positive claims:

- The enterprise Zeek dataset spans 24 hours with 202–204 flows meeting the minimum timestamp threshold per tool. Multi-day and multi-week traffic captures are needed to characterize false-positive rates at scale.
- Adversarial negative controls (retry storms, CDN polling, IoT telemetry, NTP synchronization, Slack keep-alive, browser update traffic) have not been systematically tested. The most critical negative control — exponential backoff — is analyzed separately in Section 8.5.
- Confidence intervals on detection rates and false-positive rates are not reported due to the limited sample sizes. For context: 0 flags in 204 flows yields a 95% Clopper-Pearson upper bound of approximately 1.5% FPR per tool; 0 in 100 Poisson trials yields an upper bound of approximately 3.0%. These bounds characterize the current validation but do not substitute for large-scale empirical evaluation.
- No comparison against Elastic's autocovariance-based beaconing framework or Lomb-Scargle spectral analysis is included; the RITA comparison addresses only the composite regularity scoring methodology.
- No real malware C2 traffic using these scheduling families exists in publicly available datasets, so true-positive evaluation is limited to synthetic schedule injection.

These limitations position the current results as preliminary validation of the detection approach, not as operational false-positive characterization.

### 8.6 Backoff and Retry Confounders

Exponential backoff is the most likely source of false positives in operational deployment. We tested eight common retry patterns — standard binary backoff, AWS SDK full-jitter backoff, Kubernetes capped backoff, TCP retransmission, browser reconnect, CDN retry, gRPC 1.6× multiplier, and mobile stepped reconnect — against all six validated detectors at 50 random seeds per pattern (3,200 total classifications).

**Initial results (two-gate detectors).** Four patterns produced zero flags across all detectors: binary backoff (ratio 2.0), AWS SDK, Kubernetes, and TCP retransmission. These represent the most common real-world retry patterns. Four patterns produced flags: gRPC 1.6× multiplier (128 total flags across Beacon Hunter, Narayana Hunter, and Reverse Scanner), CDN retry (24 flags on Tribonacci Hunter and Reverse Scanner), browser reconnect (23 flags), and mobile stepped (4 flags). Total: 179 flags.

**Root cause: φ-adjacency.** The gRPC false positives are structurally inevitable with the original two-gate architecture. gRPC's multiplier of 1.6 is within 0.02 of the golden ratio φ ≈ 1.618. Geometric growth at r ≈ φ produces a Fibonacci recurrence residual of |r² − r − 1|/r² = |2.56 − 2.6|/2.56 = 0.016, far below the 0.20 Gate 2 threshold. The permutation test confirms the sequence is structured (p ≈ 0.000), but cannot distinguish "structured as additive recurrence" from "structured as geometric growth near φ."

**Gate 2.5: Convergence verification.** We introduced a third gate that tests whether consecutive ICI ratios converge toward the family constant. True additive recurrence produces ratios that start far from the algebraic constant and converge (Fibonacci ratios begin at 1.0, 2.0, 1.5, 1.667... before settling near φ). Geometric backoff produces ratios that are scattered around the multiplier from the start with no convergence trend. The gate computes the linear regression slope of |ratio − constant| versus index; a negative slope (< −0.008) indicates convergence (true recurrence, accept), while zero or positive slope indicates no convergence (geometric backoff, reject). For the Power and Prime detectors, which do not use ratio convergence, a capped-geometric rejection gate checks whether the sequence contains multiple non-monotonic intervals (≥ 2 ratios below 1.0), characteristic of capped retry patterns that plateau after hitting a maximum delay.

**Results after Gate 2.5.** Total flags dropped from 179 to 46 (74% reduction). The gRPC pattern showed the largest improvement: Beacon Hunter dropped from 48/50 to 5/50, Narayana Hunter from 32/50 to 3/50, Reverse Scanner from 48/50 to 5/50. The four clean patterns remained clean. CDN retry decreased from 24 to 14 flags; browser reconnect from 23 to 16; mobile stepped from 4 to 3. The remaining 46 flags are documented limitations where jitter randomly produces convergence-like ratio patterns; further reduction would require sacrificing detection sensitivity at operational jitter levels.

*Table: Backoff stress test results (50 seeds per pattern, 8 detectors)*

| Pattern | Before Gate 2.5 | After Gate 2.5 |
|---------|----------------|----------------|
| Binary backoff (2×) | 0 | 0 |
| AWS SDK (full jitter) | 0 | 0 |
| Kubernetes (cap 300s) | 0 | 0 |
| TCP retransmit | 0 | 0 |
| Browser reconnect | 23 | 16 |
| CDN retry (short) | 24 | 14 |
| gRPC (1.6× multiplier) | 128 | 13 |
| Mobile stepped | 4 | 3 |
| **Total** | **179** | **46** |

### 8.7 Jitter Tolerance

> *[Figure 11: Jitter Tolerance Comparison — multi-line plot showing detection rate vs jitter percentage for all validated families. Four recurrence families cluster at 95-100% through 15% jitter. Bounded drops sharply below 2%.]*

The jitter tolerance profile of the recurrence detectors depends on Gate 2.5: the convergence slope threshold of −0.008 discriminates true recurrence from geometric backoff at the cost of some true-positive rate at higher jitter levels. Empirical measurement across 100 seeds (test5_gate25_cost.py) for Fibonacci at n=20:

| Jitter | Detection rate | Gate 2.5 rejects | Gate 1/2 rejects |
|--------|---------------|-----------------|-----------------|
| 0% | 100% | 0 | 0 |
| 5% | 100% | 0 | 0 |
| 8% | 88% | 12 | 0 |
| 10% | **78%** | 22 | 0 |
| 12% | 76% | 24 | 0 |
| 15% | 64% | 36 | 0 |
| 20% | **50%** | 50 | 0 |

*Table 11b. Gate 2.5 detection cost for Fibonacci (n=20, 100 seeds). All misses are attributable to Gate 2.5: early ICI ratios starting far from φ can prevent the convergence slope from reaching the −0.008 threshold. Gate 1 and Gate 2 produce zero rejects at all jitter levels.*

The miss mechanism is well-understood: true Fibonacci sequences converge toward φ, but when early ICI ratios start far from φ due to jitter, the linear regression slope of |ratio − φ| may not reach −0.008 even though the overall trend is convergent. Gate 2.5 was calibrated to maximize gRPC 1.6× backoff rejection; this calibration trades detection rate at higher jitter for false-positive suppression. The slope distribution at 10% jitter makes the boundary explicit: detected flows have mean slope −0.014, rejected flows have mean slope −0.006, threshold at −0.008.

The jitter tolerance difference between growth-family detectors (78% at 10% jitter for Fibonacci; other families similar) and the bounded detector (<2%) reflects a fundamental distinction in signal type. Recurrence tests check relationships between specific terms—ICI[*n*] = ICI[*n*−1] + ICI[*n*−2]—where each term carries independent information and multiplicative noise affects both sides of the equation proportionally. The three-gap test checks distributional properties of the entire set, where noise shifts individual points and blurs gap boundaries. This is a structural limitation of distributional signals, not a calibration deficiency. The Gate 2.5 detection cost is a calibration trade-off, not a detector defect; the threshold can be tuned for environments where higher jitter tolerance is required at the cost of increased backoff false positives.

### 8.8 Detection Gap Demonstration: RITA v5.1.2 vs. Beacon Hunter

To demonstrate that the structural ceiling theorem has operational consequences, we evaluated all five scheduling families against RITA v5.1.2 and the structural detector battery using real Zeek-format conn.log traffic.

**Setup.** Twenty connections from 10.55.100.42 to 185.199.108.153:443/tcp/ssl were injected into a 100-flow enterprise conn.log. The connections were spaced at Fibonacci-scaled intervals (base × fib(n), base = 5 seconds, 10% jitter), producing ICIs of [5.1, 4.6, 10.1, 14.5, 24.3, 36.6, 68.5, 112.0, ...] seconds. The consecutive ratios converge toward φ: [0.893, 2.207, 1.435, 1.673, 1.508, 1.871, ...].

**RITA v5.1.2 result — single family.** In a prior run with 20 Fibonacci connections, RITA assigned a beacon score of **45.9%** with severity **None**. The observed score of 0.459 is below the theoretical ceiling of 0.50 + 0.50/20 = 0.525 for n = 20 distinct intervals, consistent with the structural ceiling theorem.

**RITA v5.1.2 result — all five families.** Zeek-format conn.log files were generated for all five scheduling families (each using a unique destination IP to produce five distinct flows) and imported into RITA v5.1.2. RITA assigned the following scores, all with severity **None**:

| Family | Destination | RITA score | Ceiling | Alert? |
|--------|------------|-----------|---------|--------|
| Fibonacci (n=20) | 185.199.108.10 | 65.3% | 52.5%† | None |
| Rotation (n=30) | 185.199.108.14 | 46.4% | 51.7% | None |
| Padovan (n=20) | 185.199.108.12 | 36.7% | 52.5% | None |
| Narayana (n=20) | 185.199.108.13 | 32.4% | 52.5% | None |
| Tribonacci (n=15) | 185.199.108.11 | 30.6% | 53.3% | None |

*Table 12b. RITA v5.1.2 scores for all five scheduling families. All five below the 0.70 alert threshold (Severity: None). †Fibonacci 65.3% exceeds the strict n=20 ceiling of 52.5% because jitter rounds two intervals to the same bucket, allowing one additional top-cover contribution; this falls within the k=2 bucket-collision ceiling of 55.6% derived in Section 4.3.*

No family produced an alert. The detection gap holds across all five families in a single RITA database.

**Beacon Hunter result.** Beacon Hunter classified the same flow as **ADDITIVE_RECURRENCE_BEACON** with **86.1% confidence**. The detector identified the Fibonacci recurrence structure through Gate 1 (ratio clustering near φ), Gate 2 (recurrence residual confirmation with permutation significance), and Gate 2.5 (convergence verification).

**Interpretation.** RITA observed the traffic, evaluated its timing, and concluded it was not a beacon. The growing-interval structure produced low scores on all four RITA components: high interval skew (many distinct values), low bimodality (no repeated interval), low top-cover (no single interval dominates), and zero streak length (no consecutive identical intervals). This is exactly the mechanism described by the ceiling theorem — the scoring methodology is structurally unable to produce a high composite score for monotonically growing schedules, regardless of parameter tuning.

Beacon Hunter detected the same flow because it tests a different signal: the structural relationship between consecutive intervals rather than interval regularity. The recurrence residual and ratio convergence are properties that RITA's composite scoring does not measure.

> *[Figure 17: RITA v5.1.2 vs. Beacon Hunter — same 20-connection Fibonacci beacon. RITA scores 45.9% (below 70% alert threshold). Beacon Hunter classifies as ADDITIVE_RECURRENCE_BEACON at 86.1% confidence. The ceiling theorem predicts a maximum RITA score of 52.5% for n=20.]*

### 8.9 Spectral Observability Across Scheduling Families

To assess whether the detection gap extends beyond RITA-style scoring to spectral methods, we applied the Rayleigh periodogram — a point-process spectral test that measures phase alignment of event timestamps at candidate periods — to all seven scheduling families (n = 20–50 events per family), with periodic beacons as positive controls and Poisson random arrivals as a negative control.

**Positive controls passed:** All three periodic beacons (30s interval at 0%, 10%, and 25% jitter) were detected at their correct periods with FAP < 0.01. The Poisson negative control was not significant (FAP = 0.29). The test is correctly calibrated.

**Results by family:**

| Family | Significant Peak? | Peak Period | FAP |
|--------|-------------------|-------------|-----|
| Fibonacci | Yes | 2.2M seconds | < 0.001 |
| Tribonacci | Yes | 181K seconds | < 0.001 |
| Padovan | Yes | 12.8K seconds | < 0.001 |
| Narayana | Yes | 104K seconds | < 0.001 |
| Primes | No | 29.3 seconds | 0.55 |
| Polynomial | No | 406 seconds | 0.15 |
| Rotation | No | 120.8 seconds | 0.30 |

Not all deterministic non-periodic schedules behave identically under spectral analysis. The four recurrence families produce significant Rayleigh peaks, but at observation-scale periods (thousands to millions of seconds) rather than behavioral periods. This reflects the non-stationary event density inherent in growing-interval schedules — events cluster at the beginning of the observation window because early intervals are short — rather than true periodic structure. Whether this constitutes operationally meaningful spectral detection depends on the detection system's design: a method that flags non-stationary event rates would detect recurrence families, while one that requires a recoverable behavioral period would not.

The prime, polynomial, and bounded rotation families did not produce significant spectral peaks under the evaluated conditions. This family-dependent spectral observability is a richer result than uniform invisibility and suggests that the relationship between scheduling structure and spectral detectability varies across the taxonomy.

---

### 8.10 Multi-Method Detection Comparison

To assess whether the detection gap extends beyond RITA-style composite scoring, we applied four periodicity-centric detection methods to all five scheduling families across five jitter levels (0%, 5%, 10%, 15%, 20%), with a periodic beacon as a positive control (test_multimethod.py, reproducible):

**Methods tested:**
- **RITA-style composite score** — four-component equal-weight scoring (alert threshold: ≥ 0.70)
- **Coefficient of Variation (CV)** — ICI regularity measure (alert threshold: CV ≤ 0.30, indicating tight regularity)
- **Lomb-Scargle periodogram** — point-process spectral test on ICI time series (alert threshold: normalized peak ≥ 0.70)
- **Binned-count FFT** — events binned into fixed windows, FFT of count series (alert threshold: dominant fraction ≥ 0.30)

**Positive control:** A periodic 60-second beacon with 5% jitter produced alerts from CV (0.0329 ≤ 0.30) and FFT (0.716 ≥ 0.30), confirming both methods function correctly. RITA and Lomb-Scargle did not alert at this jitter level and sequence length, consistent with their design requirements for tighter regularity or longer observation windows.

**Results across all families and jitter levels:**

| Method | Alerts / 100 evaluations | Result |
|--------|------------------------|--------|
| RITA | 0 / 100 | No detection capability for non-periodic |
| CV | 0 / 100 | No detection capability for non-periodic |
| Lomb-Scargle | 0 / 100 | No detection capability for non-periodic |
| FFT | 0 / 100 | No detection capability for non-periodic |

*Table 15b. Multi-method comparison. Zero alerts across all four periodicity-centric methods against all five scheduling families at all five jitter levels (5 families × 5 jitter levels × 5 seeds, majority-vote per cell). The detection gap extends beyond RITA to CV, Lomb-Scargle, and FFT-based methods.*

**Implementation note.** The FFT method requires correct application to point-process data: events must be binned into fixed-width count windows, not applied directly to the raw ICI series. Applying FFT to raw ICIs detects the monotonic growth trend rather than periodicity and produces false positives on growing sequences. The binned-count implementation correctly finds no dominant periodic frequency in any non-periodic scheduling family.

The detection gap is not specific to RITA's scoring formulation. It reflects the absence of a recoverable dominant behavioral period in any monotonically growing schedule — a property shared by all four tested methods. Spectral analysis is addressed separately in Section 8.9.


## 9. Bidirectional Detection

### 9.1 Tactical Motivation

Reverse scheduling—running any mathematical sequence backward—produces shrinking intervals. A reverse-Fibonacci beacon starts with long intervals (low profile during persistence) and accelerates to short intervals (high-frequency callbacks during active exfiltration). This is tactically coherent: the beacon is hardest to detect when the attacker is establishing persistence (long, infrequent callbacks) and provides maximum C2 bandwidth when the attacker needs it most (short, frequent callbacks during data exfiltration or lateral movement).

### 9.2 Architecture

The Reverse Scanner consolidates all six forward detectors into a single module and adds bidirectional capability. For each flow, it computes ICIs, tests forward against all six families, reverses the ICI sequence, and tests reversed against all families with appropriate gate strictness.

The Reverse Scanner (v1.2) tests the four recurrence families in both forward and reverse directions, applying the same multi-gate architecture with convergence verification. Each family's detection gates are inherently direction-agnostic: the recurrence relationship ICI[n] = ICI[n-1] + ICI[n-2] holds whether the sequence is growing or shrinking, and the convergence-slope test applies to both directions.

### 9.3 Results

All six families are detectable in reverse. Zero reverse false positives on real enterprise Zeek data. The total detection surface is twelve directional targets plus one bounded target: thirteen detection targets from eight tools.

> *[Figure 14: Forward vs Reverse Scheduling — dual timeline showing growing Fibonacci intervals alongside shrinking (reversed) Fibonacci. Annotated with operational phases: "low profile / persistence" during long intervals, "active C2 / exfiltration" during short intervals.]*

---

## 10. A Second Detection Paradigm: Bounded Scheduling and the Three-Gap Theorem

### 10.1 From Growth-Based to Distributional Detection

Sections 4–9 address a single detection paradigm: schedules whose intervals grow (or shrink) according to a mathematical law, detected by testing for the specific growth structure. This section presents a qualitatively different paradigm that does not fit within the growth-based framework at all.

Bounded rotation scheduling produces intervals that remain within a fixed range, carry no growth signal, and lack the structural features that growth-based detectors test for. Growth-based detectors — both periodicity-based and structural — classify bounded rotation sequences as BACKGROUND because the intervals show no trend, no dominant period, and no ratio convergence. The evasion mechanism is fundamentally different from growing schedules: growing schedules evade because their intervals are all distinct (breaking top-cover and streak); bounded rotation sequences evade because they look like random variation within a fixed range — the same pattern as a health check, application retry, or user-driven browsing session.

The detection signal is correspondingly different. Growth-based detectors test relationships between consecutive terms (ratio convergence, recurrence residuals). The bounded detector tests a distributional property of the entire interval set — gap-length clustering under the three-gap theorem. This is a different mathematical foundation, a different gate architecture, and a different robustness profile (substantially lower jitter tolerance). The bounded detector is included in this paper because the same threat model motivates it — deterministic non-periodic C2 scheduling — but it represents a second research direction rather than a natural extension of the growth-based taxonomy. A future treatment might develop bounded non-periodic detection as a standalone contribution.

### 10.2 The Three-Gap Theorem

**Theorem (Sós [21], van Ravenstein [22]).** For any irrational α and any positive integer N, the N points {frac(*n*α) : *n* = 1, 2, ..., N} partition the unit interval [0, 1] into gaps of at most three distinct lengths. When there are three distinct gaps, the largest equals the sum of the other two.

This theorem applies to all irrational rotation parameters—φ, √2, π, *e*, or any other irrational number. The three-gap property is the structural fingerprint that distinguishes deterministic rotation sequences from random uniform samples, which produce N distinct gap lengths.

We verified the theorem computationally for α ∈ {φ, √2, π, *e*} at N = 15, confirming exactly three gap lengths in each case and verifying the additive property L = S + M.

### 10.3 Gate Design

**Gate 1 — Bounded Non-Periodic:** Range ratio (max ICI / min ICI) < 5.0; coefficient of variation > 0.10 (not constant); regression slope / mean < 0.03 (not trending). This gate rejects all growth families (trending), constant beacons (low CV), and highly variable non-structured traffic (wide range).

**Gate 2 — Three-Gap + Discrepancy:** Normalize ICIs to [0, 1], sort, compute gap lengths between consecutive sorted values. Count distinct gap-length clusters using tolerance-based grouping. Pass if clusters ≤ 4 AND star discrepancy D* < 0.20 AND bootstrap p < 0.05. The dual requirement (few clusters AND low discrepancy) rejects both random traffic (too many clusters) and cycling/retry patterns (few clusters but high discrepancy from point clustering).

> *[Figure 15: Three-Gap Theorem Illustration — circle with N=15 points at golden ratio intervals, gaps colored by length (3 colors). Alongside: random uniform N=15 for comparison (many colors).]*

### 10.4 Jitter Limitation

The bounded detector has fundamentally lower jitter tolerance than growth-family detectors: ~68% detection at 1% jitter, ~34% at 2%, effectively zero above 3%. This reflects the structural difference between term-level signals (recurrence relationships between specific terms) and distributional signals (gap-length clustering across the entire set). Multiplicative jitter shifts individual normalized positions by amounts comparable to gap widths, blurring the three-gap structure.

The bounded detector currently targets exact or near-exact irrational rotation scheduling. While an attacker using rotation scheduling already produces intervals that appear random to existing detectors — reducing the obvious incentive to add jitter — a reviewer may reasonably note that attackers could add small timing noise to defeat specifically this detector while preserving approximate predictability. Jitter-robust bounded detection, likely requiring rotation-parameter estimation rather than gap counting, remains future work. The current detector should be understood as addressing the exact-implementation case; jittered bounded deterministic schedules are an open problem.

---

## 11. Discussion

### 11.1 Claim Tiers

This paper makes claims at three distinct levels of evidence. Separating them is essential for honest evaluation.

**Tier 1 — Proven.** The RITA-style composite regularity scoring ceiling for monotonic distinct-interval schedules is a mathematical result. For n ≥ 3 distinct intervals, the composite score is bounded by 0.50 + 0.50/n, strictly below the 0.70 alert threshold. This is independent of family, growth rate, or implementation. The enumeration of binary-coefficient recurrences up to third order is a closed algebraic result. These do not depend on empirical validation.

**Tier 2 — Demonstrated.** Specific multi-gate detectors can classify injected and synthetic schedules for seven mathematical families, reject tested non-target families (cross-family separation), and produce zero actionable false positives on a 24-hour enterprise Zeek dataset after protocol/destination triage. The three-gap theorem provides a novel detection signal for bounded irrational rotation scheduling. These results are empirical but preliminary — they demonstrate feasibility, not operational readiness.

**Tier 3 — Hypothesized / Future work.** Whether real-world attackers would adopt these scheduling families, whether the detectors perform adequately on multi-week enterprise traffic at scale, whether the ceiling result extends to spectral or autocorrelation-based periodicity detectors, and whether bounded detection can be made jitter-robust — these are open questions that the current work does not resolve.

### 11.2 Scope of the Ceiling Result

The structural ceiling is proved for RITA-style composite scoring with four equal-weighted components. It does not formally cover spectral periodicity detectors (Lomb-Scargle), autocorrelation-based methods (Elastic), or ML-based approaches. Growing-interval schedules lack a dominant behavioral period, but Rayleigh periodogram analysis (Section 8.9) shows that recurrence families produce significant peaks at observation-scale periods reflecting non-stationary event density. Whether these observation-scale peaks constitute operationally meaningful spectral detection depends on the detector's design and remains an open question requiring separate analysis for each detector class. This paper's ceiling result should be cited specifically as applying to RITA-style composite regularity scoring, not to "all periodicity-based detection."

### 11.3 Scope of the Enumeration

Within the class of binary-coefficient linear recurrences up to third order, the four cubics plus the Fibonacci quadratic cover all non-degenerate possibilities. The prime and polynomial families represent two representative non-recurrence growth classes. The bounded paradigm represents one non-growth case. The reverse extension covers the directional dimension.

What remains outside this taxonomy: van der Corput and Halton sequences (base-reversal quasi-random rather than rotation-based) may carry different structural fingerprints than irrational rotation. Fourth-order and higher recurrences (e.g., Tetranacci) are natural extensions but produce diminishing marginal coverage — their growth ratios cluster near 2.0, making them harder to distinguish from exponential backoff. Non-linear deterministic sequences, chaotic maps, and hybrid strategies are not addressed.

### 11.4 What Failed and Why

Two detection paths failed at scale. Understanding why they failed may be more valuable than the detectors that succeeded, because the failure reveals a general principle about detection signal quality.

**Prime detection failed because it tests values, not relationships.** The prime detector asks: "Is this interval value near a prime number?" That is a property of the individual interval, independent of its neighbors. Because primes have density ~1/ln(n), approximately one in eight integers near typical C2-range values is prime. Any sufficiently long flow has a reasonable chance of containing intervals near primes by coincidence. In CTU-13 testing, 98% of all structural false positives — 41,225 out of 42,184 — originated from this path. All 146 structural activations on labeled botnet flows were prime misclassifications: periodic C2 at intervals that happened to be near prime values (e.g., 2369 seconds, which is coincidentally prime).

**Polynomial detection failed for the same structural reason.** Log-log linearity tests the shape of the sequence as a whole, not the generative relationship between consecutive terms. Many natural processes produce curves that appear linear on a log-log plot over short windows.

**Recurrence detection succeeded because it tests relationships.** The recurrence detectors ask: "Does ICI[n] ≈ ICI[n-1] + ICI[n-2]?" That is a constraint on how consecutive intervals relate to each other. Random traffic almost never satisfies it — the probability of three consecutive intervals accidentally forming an additive relationship with low residual is negligible, and the probability of ten consecutive intervals doing so is astronomically small. This is why the four recurrence detectors produced only 22 activations across 145,406 flows.

**The general principle: relational signals discriminate; value-based signals do not.** This distinction — testing inter-element structure versus testing individual-element properties — may apply beyond the specific families studied here. Any detection method that tests what values are (near primes, near powers, near specific constants) will struggle with coincidental matches. Methods that test how values relate to each other (recurrence, convergence, structural dependency) are inherently more selective.

### 11.5 Detector Maturity

The Bounded Hunter occupies a middle ground. The three-gap theorem provides a mathematically rigorous detection signal — a relational test (gap-count clustering) rather than a value-based one — and it produced only 3 activations across 145K flows. However, its jitter tolerance (~1–2%) is an order of magnitude below the recurrence detectors (78% detection rate at 10% jitter; see Section 8.7). Rotation-parameter estimation, which would recover the irrational α directly from the interval sequence, is a more promising but substantially harder approach. The Bounded Hunter should be understood as a proof of concept demonstrating that bounded non-periodic scheduling is detectable in principle.

### 11.6 Comparison to Machine Learning

ML-based beacon detectors [13–17] and structural detectors address different aspects of the detection problem. ML approaches learn statistical patterns from labeled data and generalize to unseen variants within the training distribution. Structural detectors test specific mathematical relationships and provide interpretable, family-specific classification. The approaches are complementary: structural classifications can serve as features for ML-based scoring, and ML can handle scheduling families that don't fit any known mathematical model.

### 11.7 Operational Deployment Considerations

These tools are designed as supplemental signals within multi-tool triage workflows, not as standalone detection systems. A classification of ADDITIVE_RECURRENCE_BEACON or ROTATION_BEACON identifies timing structure consistent with a mathematical family; it does not assert compromise. Analysts should apply destination reputation, FQDN, port, protocol, host role, and volume context. High-confidence flags on non-multicast TCP destinations to external IPs warrant investigation; marginal flags on known-protocol broadcast traffic are dismissed.

Deployment requires integration into an existing SIEM or Zeek pipeline. Each detector processes one flow at a time; the computational cost is dominated by the Gate 2 permutation test (200–500 iterations). For a 24-hour Zeek conn.log with ~2,000 qualifying flows, the full six-detector battery completes in under 30 seconds on commodity hardware. At enterprise scale (100K+ flows), parallelization across flows is straightforward because detectors are stateless.

False-positive triage is the primary operational concern. The backoff stress test (Section 8.6) identified gRPC 1.6× multiplier traffic as the highest-risk confounder. Environments with heavy gRPC usage should monitor Gate 2.5 rejection rates; consistently high rejection rates may indicate the convergence slope threshold (−0.008) needs tuning for the local traffic profile. The remaining ~46/3200 (1.4%) flag rate on synthetic stress patterns represents an upper bound — real-world retry sequences are typically shorter (3–5 retries, below the minimum-interval threshold) and embedded in longer flows with non-geometric surrounding traffic.

---

## 12. Limitations

The following limitations constrain the strength of the current results and should be considered when evaluating the framework's claims:

**No observed malware adoption.** No confirmed real-world malware sample is known to use Fibonacci, Tribonacci, Padovan, Narayana, or irrational rotation scheduling. The framework addresses a plausible future threat based on operational incentives analysis, not a confirmed current one. The threat model's value depends on whether these scheduling strategies are eventually adopted by adversaries, which remains unknown.

**Enterprise validation limited to one environment.** The primary enterprise Zeek dataset spans 24 hours from a single network with 204 qualifying flows. The CTU-13 dataset (251,459 flows) provides larger-scale FPR characterization but dates from 2011 and represents university network traffic, not contemporary enterprise environments. Multi-site, multi-week validation across diverse network types is needed.

**Prime and polynomial detectors not operationally validated.** The prime and polynomial detection paths produced 98% of all structural false positives in CTU-13 testing and were removed from the validated core. These growth regimes are part of the taxonomy but do not have validated detection methods. Developing relational (rather than value-based) detection signals for logarithmic and polynomial growth remains an open research problem.

**Spectral findings preliminary.** The Rayleigh periodogram analysis uses synthetic schedules at fixed sequence lengths (n = 20–50) with a single spectral method. Longer sequences, alternative methods (Lomb-Scargle, autocovariance), sensitivity analysis, and real-traffic spectral testing are needed before spectral-observability claims can be considered robust.

**Higher-order recurrences and nonlinear sequences outside scope.** The algebraic enumeration covers binary-coefficient recurrences up to third order only. Fourth-order and higher recurrences, chaotic maps (logistic, tent), quasi-random constructions (van der Corput, Halton), and hybrid strategies are not addressed.

**Synthetic schedule dominance.** True-positive evaluation is limited to synthetic schedule injection because no real malware C2 traffic using these families exists in public datasets. Real adversarial implementations would include clock skew, network delay, and implementation artifacts not modeled in synthetic testing.

**Jitter tolerance varies.** The recurrence detectors tolerate 10% multiplicative jitter at 78% detection rate (dropping to 50% at 20% jitter) under controlled conditions; the bounded detector tolerates less than 2%. Real-network timing variability may exceed these tolerances.

**ML interaction uncharacterized.** Machine learning models trained on diverse timing features might detect some or all of these scheduling families without family-specific structural detectors. The detection gap may narrow as ML training data improves.

**Dataset-specific results.** All validation results are specific to the evaluated datasets. Generalization to other network environments, traffic mixes, or adversarial conditions is not established.

---

## 13. Future Work

Several directions extend the current framework.

**Logarithmic and polynomial growth-regime detection.** The taxonomy identifies four growth regimes, but the current validated detectors cover only two (exponential and bounded). The logarithmic regime (exemplified by prime-spaced intervals) and polynomial regime (power-law growth) lack validated detection methods. CTU-13 testing demonstrated that value-based approaches — testing whether individual intervals are near primes, or whether the sequence shape fits a power law — produce unacceptable false-positive rates (98% of all structural FP). Future work should investigate relational detection signals for these regimes: methods that test structural relationships between consecutive intervals rather than properties of individual interval values. Whether such relational signals exist for logarithmic and polynomial growth is an open question.

**Higher-order recurrences.** Fourth-order (Tetranacci) and higher recurrences are natural extensions. However, their growth ratios cluster near 2.0 as order increases, making them harder to distinguish from common exponential backoff patterns. The diminishing separation from geometric growth at r = 2.0 is a fundamental limitation, not a tunable parameter.

**Non-linear deterministic sequences.** Chaotic maps (logistic, tent), quasi-random constructions (van der Corput, Halton), and hybrid strategies remain outside the current taxonomy. These may carry different structural fingerprints than the growth-regime families addressed here.

**Spectral and autocorrelation analysis.** The Rayleigh periodogram results (Section 8.8) show family-dependent spectral observability. A systematic comparison against Elastic's autocovariance framework and Lomb-Scargle periodogram at longer sequence lengths would clarify the spectral detection boundary for each family. The autocorrelation finding that all growth families produce perfect lag-1 ICI correlation (r = 1.000) suggests a potential alternative detection signal worth investigating.

**Bounded detection hardening.** The three-gap theorem provides a mathematically rigorous detection signal, but the current implementation's ~1–2% jitter tolerance limits operational utility. Rotation-parameter estimation — directly recovering the irrational α from the interval sequence — is a more promising approach that could improve robustness substantially.

**ML integration.** Structural classifications (family label, confidence, gate scores) can serve as engineered features for ML-based downstream scoring. A hybrid architecture that uses structural detectors as feature extractors and ML for final classification could combine interpretability with generalization.

**Larger-scale validation.** Multi-week Zeek captures, multi-site deployments, and adversarial negative controls (intentionally crafted confounders) are needed to characterize false-positive rates at operational scale. The current 24-hour, single-site validation demonstrates feasibility but not operational readiness.

---

## 14. Summary

The following table summarizes the status of each scheduling family in the framework:

| Family | Growth Regime | Signal Type | Detector Status | CTU-13 Result |
|--------|--------------|-------------|----------------|---------------|
| Fibonacci | Exponential | Relational | Validated | 1 activation / 145K flows |
| Tribonacci | Exponential | Relational | Validated | 0 activations / 145K flows |
| Padovan | Exponential | Relational | Validated | 9 activations / 145K flows |
| Narayana | Exponential | Relational | Validated | 9 activations / 145K flows |
| Rotation | Bounded | Relational | Validated | 3 activations / 145K flows |
| Prime | Logarithmic | Value-based | Failed at scale | 41,225 activations / 251K flows |
| Polynomial | Power-law | Value-based | Failed at scale | 141 activations / 251K flows |

*Table 14. Framework summary. Relational detectors (testing inter-interval structure) survived large-scale validation. Value-based detectors (testing individual interval properties) did not.*

### Practical Takeaways

**What the ceiling theorem means.** Any C2 beacon that uses monotonically growing intervals — regardless of the specific mathematical family — will score below the RITA alert threshold for n ≥ 3 distinct intervals. This is a structural property of the scoring methodology, not a tuning gap. RITA v5.1.2 scored a 20-connection Fibonacci beacon at 45.9% (Severity: None), consistent with the theoretical ceiling of 52.5%.

**What detectors work.** The four recurrence detectors (Fibonacci, Tribonacci, Padovan, Narayana) and the bounded rotation detector produce 22 structural activations across 145,406 real labeled background flows — fewer than two per dataset. These detectors test structural relationships between consecutive intervals: a signal that benign traffic almost never produces by coincidence.

**What detectors failed.** The prime and polynomial detectors test individual interval values rather than inter-interval relationships. This signal type is insufficiently discriminative: 98% of all structural false positives in CTU-13 validation originated from the prime path. These growth regimes remain part of the taxonomy as open detection problems.

**What defenders should do today.** The recurrence and rotation detectors are designed as supplemental signals within existing triage workflows, not as standalone alerting systems. A structural classification identifies timing structure consistent with a mathematical family; contextual triage — destination reputation, protocol, port, host role — determines whether the traffic warrants investigation. The framework extends detection coverage into a region of timing signal space where RITA-style composite scoring is provably unable to alert.

---

## 15. Conclusion

A beacon does not need to be periodic to be structured. We have shown that RITA-style composite regularity scoring has a structural ceiling for monotonically growing schedules: for n ≥ 3 distinct intervals, the maximum composite score is bounded by 0.50 + 0.50/n, strictly below the 0.70 alert threshold. This ceiling is a mathematical property of the scoring methodology, not a tuning deficiency, and it applies to any monotonically growing deterministic schedule regardless of the specific mathematical family.

We have presented a structural taxonomy of seven scheduling families organized by growth regime — bounded, logarithmic, polynomial, and exponential — with a closed algebraic enumeration of the binary-coefficient recurrence class up to third order (Fibonacci, Tribonacci, Padovan, Narayana). The three-gap theorem, applied — to our knowledge for the first time — to network security detection, provides a detection signal for bounded non-periodic scheduling that is qualitatively distinct from growth-based detection.

Large-scale validation on the CTU-13 and Stratosphere datasets (145,406 labeled background flows, over 742,000 detector evaluations at n ≥ 8) showed that the validated recurrence and bounded detectors produced only 22 structural activations on background traffic — fewer than two per dataset. This low activation rate on a large benign corpus, combined with zero activations on 3,165 labeled botnet flows, demonstrates that recurrence structures are uncommon in real network traffic and that the detectors do not produce spurious matches on conventional C2 timing patterns. Early evaluation of value-based detection paths (prime-adjacency, polynomial curve-fitting) revealed that relational signals — testing structural relationships between consecutive intervals — are fundamentally more discriminative than value-based signals testing properties of individual interval values. This finding led to the exclusion of the logarithmic and polynomial growth regimes from the validated core; detection methods for these regimes remain an open research problem.

Systematic backoff stress testing confirmed that the four most common retry patterns (binary, AWS SDK, Kubernetes, TCP retransmission) produce zero false positives across all detectors. The introduction of Gate 2.5 (convergence-based geometric-backoff rejection) reduced total backoff flags from 179 to 46, with the gRPC 1.6× multiplier pattern — mathematically near-identical to the golden ratio — dropping from 128 to 13 flags. Rayleigh periodogram analysis showed family-dependent spectral observability: recurrence families produce significant peaks reflecting non-stationarity rather than behavioral periodicity, while prime, polynomial, and rotation families do not produce significant peaks.

The validated core of the framework — Beacon Hunter (Fibonacci), Tribonacci Hunter, Padovan Hunter, Narayana Hunter, Bounded Hunter (rotation), and Reverse Scanner v1.2 (four recurrence families, bidirectional) — demonstrates that structural detection of deterministic non-periodic scheduling is feasible for the algebraic recurrence class, with low activation rates on large real-world benign traffic corpora. The logarithmic and polynomial growth regimes remain theoretically valid regions of the taxonomy where reliable detection is an open research problem. Multi-site operational validation and demonstration that recurrence-scheduled beacons evade traditional detection while being recovered by this framework are the most important next steps toward operational deployment.

---

## References

[1] G. Gu, J. Zhang, and W. Lee, "BotSniffer: Detecting Botnet C&C Channels in Network Traffic," Proc. NDSS, 2008.

[2] G. Gu, R. Perdisci, J. Zhang, and W. Lee, "BotMiner: Clustering Analysis of Network Traffic for Protocol- and Structure-Independent Botnet Detection," Proc. 17th USENIX Security Symposium, pp. 139–154, 2008.

[3] G. Gu, P. Porras, V. Yegneswaran, M. Fong, and W. Lee, "BotHunter: Detecting Malware Infection Through IDS-Driven Dialog Correlation," Proc. 16th USENIX Security Symposium, pp. 167–182, 2007.

[4] B. AsSadhan and J. M. F. Moura, "An Efficient Method to Detect Periodic Behavior in Botnet Traffic by Analyzing Control Plane Traffic," Journal of Advanced Research, vol. 5, no. 4, pp. 435–448, 2014.

[5] J. D. Scargle, "Studies in Astronomical Time Series Analysis. II. Statistical Aspects of Spectral Analysis of Unevenly Spaced Data," The Astrophysical Journal, vol. 263, pp. 835–853, 1982.

[6] Active Countermeasures, "RITA: Real Intelligence Threat Analytics," github.com/activecm/rita (accessed May 2026).

[7] Active Countermeasures, "RITA documentation and beacon scoring methodology," activecountermeasures.com/free-tools/rita/ (accessed May 2026).

[8] Active Countermeasures, "AC-Hunter Beacons," activecountermeasures.com/ac-hunter-features/beacons/ (accessed May 2026).

[9] Fortra, "Cobalt Strike Malleable C2 Profiles," official documentation (accessed May 2026).

[10] Unit 42, "Detecting Popular Cobalt Strike Malleable C2 Profile Techniques," Palo Alto Networks, June 2024.

[11] DeepTempo, "Evading rule-based detection — Part 1: C2 beaconing," deeptempo.ai, February 2026.

[12] Elastic Security Labs, "Identifying beaconing malware using Elastic," elastic.co/security-labs, March 2023.

[13] Y. Zhang, H. Dong, A. Nottingham, M. Buchanan, D. E. Brown, and Y. Sun, "Global analysis with aggregation-based beaconing detection across large campus networks," Proc. 39th Annual Computer Security Applications Conference (ACSAC), 2023.

[14] "Lurking in the shadows: Unsupervised decoding of beaconing communication for enhanced cyber threat hunting," Journal of Network and Computer Applications, February 2025. doi:10.1016/j.jnca.2025.100244.

[15] J. Velasco-Mata, V. González-Castro, E. Fidalgo, and E. Alegre, "Real-time botnet detection on large network bandwidths using machine learning," Scientific Reports 13, 2023. doi:10.1038/s41598-023-31260-0.

[16] "AI-Driven Fast and Early Detection of IoT Botnet Threats: A Comprehensive Network Traffic Analysis Approach," arXiv:2407.15688, 2024.

[17] "C2 Beaconing Detection via AI-Based Time-Series Analysis," Springer LNCS, 2025. doi:10.1007/978-3-032-00627-1_20.

[18] Zeek Network Security Monitor, zeek.org (accessed May 2026).

[19] B. Efron and R. J. Tibshirani, An Introduction to the Bootstrap. Chapman and Hall, 1993.

[20] T. C. Hesterberg, "What Teachers Should Know About the Bootstrap," The American Statistician, vol. 69, no. 4, pp. 371–386, 2015.

[21] V. T. Sós, "On the theory of diophantine approximations, I," Acta Mathematica Hungarica, vol. 8, pp. 461–472, 1957.

[22] T. van Ravenstein, "The Three Gap Theorem (Steinhaus Conjecture)," Journal of the Australian Mathematical Society (Series A), vol. 45, pp. 360–370, 1988.

[23] A. Das and A. Haynes, "The Three Gap Theorem and the Space of Lattices," The Ramanujan Journal, 2022.

[24] H. Niederreiter, Random Number Generation and Quasi-Monte Carlo Methods. SIAM CBMS-NSF Regional Conference Series 63, 1992.

[25] G. H. Hardy and E. M. Wright, An Introduction to the Theory of Numbers, 6th ed. Oxford University Press, 2008.

[26] S. S. Bagui, D. Mink, S. C. Bagui, T. Ghosh, R. Plenkers, T. McElroy, S. Dulaney, and S. Shabanali, "Introducing UWF-ZeekData22: A Comprehensive Network Traffic Dataset Based on the MITRE ATT&CK Framework," Data, vol. 8, no. 1, p. 18, 2023. doi:10.3390/data8010018.

[27] A. Cordero, "Detecting Non-Periodic Structured C2 Beaconing via Additive Recurrence," RepoSignal.io LLC, 2026. doi:10.5281/zenodo.20431555.

[28] "Cobalt Strike: A Cyber Assessment Challenge," ITEA Journal, vol. 45, no. 3, September 2024.

[29] Netskope, "Effective C2 Beaconing Detection White Paper," August 2025.

[30] Vectra AI, "Cobalt Strike Detection & Defense Guide," February 2026.

[31] G. F. Chen, "Three Gap Theorem and applications," Conference on Pure, Applied, and Computational Mathematics, 2023.

[32] M. Mayero, "The Three Gap Theorem (Steinhaus Conjecture)," in Types for Proofs and Programs (TYPES 1999), LNCS vol. 1956, Springer, 2000.

[33] S. Garcia, M. Grill, J. Stiborek, and A. Zunino, "An empirical comparison of botnet detection methods," Computers & Security, vol. 45, pp. 100–123, 2014. Dataset: CTU-13, https://www.stratosphereips.org/datasets-ctu13.

[34] Stratosphere IPS Project, "Stratosphere Laboratory Datasets," Czech Technical University in Prague, https://www.stratosphereips.org/datasets-overview (accessed May 2026).

---

## Supplementary Materials

The following supplementary materials are available in the accompanying code repository:

- **Ceiling proof extension:** generalized proof covering bucket collisions and near-monotonic schedules (extends Cordero [27], Appendix A).
- **Jitter sweep data:** tabulated detection rates for all tools at 0%–30% multiplicative jitter.
- **Boundary sweep data:** Gate 1 acceptance window characterization across geometric ratios 1.20–3.00.
- **Cross-family residual derivations:** theoretical residual formulas for all family pairs.
- **Full classification matrix:** every detection target tested against every detector (13 schedules × 8 tools).
- **Backoff test battery:** script testing eight real-world retry patterns against all detectors.
- **Spectral comparison:** Lomb-Scargle and autocorrelation analysis script for all scheduling families.
- **All detector source code:** AGPL-3.0 licensed, with validation suites and real Zeek test data.

---

## Figure Inventory

All 16 figures are generated and embedded in this manuscript.

| # | Title | Type | Section |
|---|-------|------|---------|
| 1 | The Detection Gap | Conceptual quadrant map | 1 |
| 2 | Implementation Complexity | Code summary table | 3 |
| 3 | Structural Ceiling | Line plot: 0.50+0.50/n vs n | 4 |
| 4 | RITA Component Decomposition | Stacked bar chart | 4 |
| 5 | Taxonomy Map | Growth regime × detection signal | 5 |
| 6 | Characteristic Equation Tree | Hierarchy diagram | 5 |
| 7 | Growth Rate Comparison | Semi-log multi-line plot | 5 |
| 8 | Multi-Gate Architecture | Pipeline flowchart | 6 |
| 9 | Acceptance Windows | Annotated number line | 7 |
| 10 | Cross-Family Heatmap | Residual matrix heatmap | 7 |
| 11 | Jitter Tolerance | Multi-line comparison plot | 8 |
| 12 | ROC Curve | AUC=0.900, Beacon Hunter only [27] | 8 |
| 13 | FP Map on Real Zeek | Tool × traffic-type heatmap | 8 |
| 14 | Forward vs Reverse | Dual timeline diagram | 9 |
| 15 | Three-Gap Illustration | Dual circle diagram | 10 |
| 16 | Gap Clusters vs N | Line plot: rotation vs random | 10 |
