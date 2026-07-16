#!/usr/bin/env python3
"""
inject_fibonacci_beacon.py
--------------------------
Injects a Fibonacci-scheduled beacon into an existing Zeek JSON conn.log.
The beacon uses realistic-looking src/dst IPs and produces ~20 connections
with Fibonacci-spaced intervals.

After running this script:
  1. Import into RITA:  rita import --rolling /path/to/combined_conn.log rita_fib_test
  2. Show beacons:      rita show-beacons rita_fib_test
  3. Run Beacon Hunter: python3 -c "from detectors.beacon_hunter import classify_flow"

The Fibonacci beacon should score BELOW RITA's 0.70 threshold (ceiling theorem)
but be DETECTED by Beacon Hunter.
"""

import json
import os
import sys
import time
import random
import string

def generate_uid():
    """Generate a Zeek-style UID."""
    chars = string.ascii_letters + string.digits
    return "C" + "".join(random.choice(chars) for _ in range(17))

def fibonacci_beacon(base_ts, base_interval=5.0, n_callbacks=20, jitter=0.10, seed=42):
    """
    Generate Fibonacci-scheduled beacon connections.
    
    ICI pattern: base * fib(1), base * fib(2), base * fib(3), ...
    = 5, 5, 10, 15, 25, 40, 65, 105, 170, 275, ...
    
    These are GROWING intervals with no dominant period.
    RITA's composite score will be bounded by 0.50 + 0.50/n.
    """
    rng = random.Random(seed)
    
    # Fibonacci sequence
    fibs = [1, 1]
    while len(fibs) < n_callbacks:
        fibs.append(fibs[-1] + fibs[-2])
    
    # Generate timestamps
    src_ip = "10.55.100.42"       # Internal IP (looks like a workstation)
    dst_ip = "185.199.108.153"    # External IP (looks like a CDN/hosting)
    dst_port = 443                # HTTPS
    
    connections = []
    current_ts = base_ts
    
    for i in range(n_callbacks):
        interval = base_interval * fibs[i]
        # Add jitter
        interval *= (1.0 + rng.uniform(-jitter, jitter))
        
        conn = {
            "ts": round(current_ts, 6),
            "uid": generate_uid(),
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
            "ip_proto": 6
        }
        connections.append(conn)
        current_ts += interval
    
    return connections


def main():
    # Input file
    input_log = os.path.expanduser("~/rita_test/conn.log")
    output_log = os.path.expanduser("~/rita_test/conn_with_fib_beacon.log")
    
    if not os.path.exists(input_log):
        print(f"Error: {input_log} not found")
        sys.exit(1)
    
    # Read existing connections
    existing = []
    with open(input_log, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                existing.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    
    print(f"Read {len(existing)} existing connections from {input_log}")
    
    # Get base timestamp from existing data
    if existing:
        base_ts = existing[0]["ts"]
    else:
        base_ts = time.time()
    
    # Generate Fibonacci beacon
    beacon = fibonacci_beacon(base_ts, base_interval=5.0, n_callbacks=20, jitter=0.10)
    
    print(f"Generated {len(beacon)} Fibonacci beacon connections")
    print(f"  Source: {beacon[0]['id.orig_h']} -> {beacon[0]['id.resp_h']}:{beacon[0]['id.resp_p']}")
    
    # Print the intervals for verification
    timestamps = [c["ts"] for c in beacon]
    icis = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    print(f"  ICIs (first 8): {[round(x, 1) for x in icis[:8]]}")
    print(f"  Ratios (first 6): {[round(icis[i+1]/icis[i], 3) for i in range(min(6, len(icis)-1))]}")
    print(f"  Note: ratios should converge toward φ ≈ 1.618")
    print()
    
    # Combine and sort by timestamp
    combined = existing + beacon
    combined.sort(key=lambda x: x["ts"])
    
    # Write output
    with open(output_log, "w") as f:
        for conn in combined:
            f.write(json.dumps(conn) + "\n")
    
    print(f"Wrote {len(combined)} connections to {output_log}")
    print()
    
    # Print the beacon flow key for later identification
    print("=" * 60)
    print("BEACON FLOW TO LOOK FOR:")
    print(f"  {beacon[0]['id.orig_h']} -> {beacon[0]['id.resp_h']}:{beacon[0]['id.resp_p']}")
    print(f"  20 connections, Fibonacci-spaced intervals")
    print()
    print("NEXT STEPS:")
    print("  1. Import into RITA:")
    print(f"     rita import {output_log} rita_fib_test")
    print("  2. Show beacons:")
    print("     rita show-beacons rita_fib_test")
    print("  3. Look for 10.55.100.42 -> 185.199.108.153")
    print("     Expected: score < 0.70 (RITA misses it)")
    print()
    print("  4. Run Beacon Hunter:")
    print("     python3 -c \"")
    print("from detectors.beacon_hunter.detectors import classify_flow")
    print(f"ts = {[round(t,3) for t in timestamps]}")
    print("r = classify_flow(ts, connection_level=True)")
    print("print(f'Classification: {r[\\\"classification\\\"]}')")
    print("print(f'Confidence: {r[\\\"confidence\\\"]}')")
    print("\"")
    print("     Expected: ADDITIVE_RECURRENCE_BEACON")
    print("=" * 60)
    
    # Also save timestamps for easy Beacon Hunter testing
    ts_file = os.path.expanduser("~/rita_test/fib_beacon_timestamps.json")
    with open(ts_file, "w") as f:
        json.dump(timestamps, f)
    print(f"\nBeacon timestamps saved to {ts_file}")


if __name__ == "__main__":
    main()
