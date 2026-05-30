#!/usr/bin/env python3
"""
generate_multiweek_traffic.py
-----------------------------
Generates realistic synthetic multi-week enterprise traffic for
false-positive rate characterization.

This generates conn.log-style timestamp data representing common
enterprise traffic patterns. Each "flow" is a series of connection
timestamps to a single destination over hours/days.

WHY THIS IS USEFUL:
Real multi-week Zeek captures require access to enterprise networks.
This synthetic traffic lets you characterize FPR against known-benign
patterns at scale (10K-100K flows) without needing network access.

The paper should describe this as:
"Synthetic multi-week enterprise traffic simulation (N flows)"
not as real-world validation.

USAGE:
  python generate_multiweek_traffic.py
  # Generates flows, tests all detectors, reports FPR
"""

import numpy as np
import json
import os
import sys
import time

# ============================================================
# TRAFFIC GENERATORS (realistic enterprise patterns)
# ============================================================

def health_check(duration_hours=24*14, interval=30.0, jitter=0.05, seed=None):
    """Application health check: periodic with low jitter."""
    rng = np.random.default_rng(seed)
    n = int(duration_hours * 3600 / interval)
    ivs = np.full(n, interval) * (1 + rng.uniform(-jitter, jitter, n))
    return np.concatenate([[0.0], np.cumsum(ivs)])

def dns_refresh(duration_hours=24*14, ttl=300.0, jitter=0.10, seed=None):
    """DNS TTL-based refresh: periodic with moderate jitter."""
    rng = np.random.default_rng(seed)
    n = int(duration_hours * 3600 / ttl)
    ivs = np.full(n, ttl) * (1 + rng.uniform(-jitter, jitter, n))
    return np.concatenate([[0.0], np.cumsum(ivs)])

def browser_keepalive(duration_hours=2, interval=45.0, jitter=0.20, seed=None):
    """Browser WebSocket keepalive: moderate jitter, session-length."""
    rng = np.random.default_rng(seed)
    n = int(duration_hours * 3600 / interval)
    ivs = np.full(n, interval) * (1 + rng.uniform(-jitter, jitter, n))
    return np.concatenate([[0.0], np.cumsum(ivs)])

def cloud_sync(duration_hours=24*14, interval=900.0, jitter=0.15, seed=None):
    """Cloud sync (OneDrive, Dropbox): 15min intervals with jitter."""
    rng = np.random.default_rng(seed)
    n = int(duration_hours * 3600 / interval)
    ivs = np.full(n, interval) * (1 + rng.uniform(-jitter, jitter, n))
    return np.concatenate([[0.0], np.cumsum(ivs)])

def ntp_sync(duration_hours=24*14, interval=1024.0, jitter=0.30, seed=None):
    """NTP sync: ~17min intervals with high jitter (poll interval varies)."""
    rng = np.random.default_rng(seed)
    n = int(duration_hours * 3600 / interval)
    # NTP poll interval varies: 64, 128, 256, 512, 1024 seconds
    poll_intervals = rng.choice([64, 128, 256, 512, 1024], size=n, p=[0.05, 0.10, 0.15, 0.30, 0.40])
    ivs = poll_intervals.astype(float) * (1 + rng.uniform(-jitter, jitter, n))
    return np.concatenate([[0.0], np.cumsum(ivs)])

def os_update_check(duration_hours=24*14, interval=3600.0, jitter=0.25, seed=None):
    """OS update checks: hourly with significant jitter."""
    rng = np.random.default_rng(seed)
    n = int(duration_hours * 3600 / interval)
    ivs = np.full(n, interval) * (1 + rng.uniform(-jitter, jitter, n))
    return np.concatenate([[0.0], np.cumsum(ivs)])

def iot_telemetry(duration_hours=24*14, interval=60.0, jitter=0.08, seed=None):
    """IoT device telemetry: very regular, low jitter."""
    rng = np.random.default_rng(seed)
    n = int(duration_hours * 3600 / interval)
    ivs = np.full(n, interval) * (1 + rng.uniform(-jitter, jitter, n))
    return np.concatenate([[0.0], np.cumsum(ivs)])

def user_browsing(duration_hours=8, seed=None):
    """User browsing session: Poisson-like with bursty periods."""
    rng = np.random.default_rng(seed)
    times = [0.0]
    t = 0.0
    end = duration_hours * 3600
    while t < end:
        # Alternate between active (λ=5s) and idle (λ=300s) periods
        if rng.random() < 0.3:
            gap = rng.exponential(5.0)
        else:
            gap = rng.exponential(300.0)
        t += gap
        if t < end:
            times.append(t)
    return np.array(times)

def slack_websocket(duration_hours=10, interval=30.0, jitter=0.15, seed=None):
    """Slack/Teams WebSocket keepalive."""
    rng = np.random.default_rng(seed)
    n = int(duration_hours * 3600 / interval)
    ivs = np.full(n, interval) * (1 + rng.uniform(-jitter, jitter, n))
    return np.concatenate([[0.0], np.cumsum(ivs)])

def cdn_polling(duration_hours=24*14, interval=120.0, jitter=0.35, seed=None):
    """CDN edge polling: moderate interval, high jitter."""
    rng = np.random.default_rng(seed)
    n = int(duration_hours * 3600 / interval)
    ivs = np.full(n, interval) * (1 + rng.uniform(-jitter, jitter, n))
    return np.concatenate([[0.0], np.cumsum(ivs)])


# ============================================================
# FLOW GENERATION
# ============================================================

TRAFFIC_TYPES = [
    ("health_check",     health_check,     100, {"duration_hours": 24*14, "interval": 30.0}),
    ("dns_refresh",      dns_refresh,       50, {"duration_hours": 24*14, "ttl": 300.0}),
    ("browser_keepalive",browser_keepalive,200, {"duration_hours": 2}),
    ("cloud_sync",       cloud_sync,        30, {"duration_hours": 24*14}),
    ("ntp_sync",         ntp_sync,          20, {"duration_hours": 24*14}),
    ("os_update",        os_update_check,   40, {"duration_hours": 24*14}),
    ("iot_telemetry",    iot_telemetry,     80, {"duration_hours": 24*14}),
    ("user_browsing",    user_browsing,    300, {"duration_hours": 8}),
    ("slack_ws",         slack_websocket,  100, {"duration_hours": 10}),
    ("cdn_poll",         cdn_polling,       50, {"duration_hours": 24*14}),
]


def generate_flows(min_timestamps=6):
    """Generate all synthetic flows."""
    flows = []
    for name, gen_fn, count, kwargs in TRAFFIC_TYPES:
        for i in range(count):
            ts = gen_fn(**kwargs, seed=i + hash(name) % 10000)
            if len(ts) >= min_timestamps:
                flows.append({
                    "type": name,
                    "seed": i,
                    "timestamps": ts,
                    "n_timestamps": len(ts),
                })
    return flows


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  MULTI-WEEK SYNTHETIC TRAFFIC GENERATOR")
    print("  Generating realistic enterprise traffic patterns")
    print("=" * 70)
    print()

    flows = generate_flows()
    total = len(flows)
    print(f"Generated {total} flows across {len(TRAFFIC_TYPES)} traffic types:")
    for name, _, count, _ in TRAFFIC_TYPES:
        actual = sum(1 for f in flows if f["type"] == name)
        print(f"  {name:25s}: {actual} flows")
    print()

    # Save timestamps for external detector testing
    output = []
    for f in flows:
        output.append({
            "type": f["type"],
            "seed": f["seed"],
            "n": f["n_timestamps"],
            "timestamps": [round(t, 3) for t in f["timestamps"][:200]],  # Cap for file size
        })

    with open("synthetic_multiweek_flows.json", "w") as fp:
        json.dump(output, fp)
    print(f"Saved {len(output)} flows to synthetic_multiweek_flows.json")
    print()

    # If detectors are available, test them
    # User should adjust these paths
    DETECTOR_PATHS = [
        ("Beacon Hunter",     "./beacon_hunter_v0_3_0"),
        ("Prime Hunter",      "./prime_hunter_v1_1"),
        ("Tribonacci Hunter", "./tribonacci_hunter_v1_1"),
        ("Padovan Hunter",    "./padovan_hunter_v1_1"),
        ("Power Hunter",      "./power_hunter_v1_1"),
        ("Narayana Hunter",   "./narayana_hunter_v1_1"),
        ("Reverse Scanner",   "./reverse_scanner_v1_1"),
        ("Bounded Hunter",    "./bounded_hunter_v1_0"),
    ]

    import importlib.util
    detectors = []
    for name, path in DETECTOR_PATHS:
        full_path = os.path.abspath(os.path.join(os.path.dirname(__file__) or '.', path))
        spec_path = os.path.join(full_path, "detectors.py")
        if not os.path.exists(spec_path):
            continue
        safe_name = name.replace(" ", "_").lower()
        spec = importlib.util.spec_from_file_location(f"det_{safe_name}", spec_path)
        mod = importlib.util.module_from_spec(spec)
        sys.path.insert(0, full_path)
        try:
            spec.loader.exec_module(mod)
            detectors.append((name, mod))
        except:
            pass
        finally:
            if full_path in sys.path:
                sys.path.remove(full_path)

    if not detectors:
        print("No detectors found. Adjust DETECTOR_PATHS to test against detectors.")
        print("You can still use the saved JSON to test externally.")
        sys.exit(0)

    print(f"Loaded {len(detectors)} detectors. Testing {total} flows...")
    print()

    results = {}
    start = time.time()
    for det_name, det_mod in detectors:
        flags = 0
        errors = 0
        flag_details = []
        for f in flows:
            try:
                r = det_mod.classify_flow(list(f["timestamps"]), connection_level=True)
                cls = r.get("classification", "UNKNOWN")
                if cls not in ("BACKGROUND", "INSUFFICIENT_DATA", "UNKNOWN",
                               "REGULAR_BEACON", "JITTERED_BEACON") \
                   and "REGULAR_BEACON" not in cls \
                   and "JITTERED_BEACON" not in cls:
                    flags += 1
                    if len(flag_details) < 5:
                        flag_details.append(f"  {f['type']} seed={f['seed']}: {cls}")
            except Exception as e:
                errors += 1

        results[det_name] = (flags, errors, total)
        rate = flags / total * 100
        print(f"{det_name:25s}: {flags}/{total} flags ({rate:.2f}%), {errors} errors")
        for d in flag_details:
            print(d)

    elapsed = time.time() - start
    print()
    print(f"Completed in {elapsed:.1f}s")
    print()

    total_flags = sum(v[0] for v in results.values())
    total_errors = sum(v[1] for v in results.values())
    print(f"Total flags: {total_flags}")
    print(f"Total errors: {total_errors}")
    if total_flags == 0 and total_errors == 0:
        print("✓ ZERO false positives across all traffic types × all detectors.")
    else:
        print(f"FPR upper bound: {total_flags}/{total*len(detectors)} = {total_flags/(total*len(detectors))*100:.3f}%")
