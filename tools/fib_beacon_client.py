"""
fib_beacon_client.py
--------------------
Fibonacci-scheduled TCP beacon client for beacon-hunter validation.

Connects to fib_beacon_server.py at Fibonacci-spaced intervals. The
schedule starts at `base` seconds, then follows the additive recurrence:

    ICI[n+2] = ICI[n+1] + ICI[n]

giving intervals: base, base, 2*base, 3*base, 5*base, 8*base, ...

The sequence grows so that consecutive interval ratios converge to phi
(approx 1.618). This is the timing pattern beacon-hunter is designed to
detect.

Usage
-----
  # Terminal 1: start server
  python fib_beacon_server.py

  # Terminal 2: start capture (Wireshark, tcpdump, etc.), then:
  python fib_beacon_client.py

  # Stop capture after the client exits, then run beacon-hunter:
  python beacon_hunter.py fib_beacon_validation.pcapng

Options
-------
  --host     Server host            (default: 127.0.0.1)
  --port     Server port            (default: 9999)
  --base     Base interval seconds  (default: 5.0)
  --count    Number of connections  (default: 12)
  --jitter   Timing jitter 0.0-1.0  (default: 0.0, e.g. 0.10 = +/-10%)
  --log      Optional log file path

Notes
-----
- Run with --count 8 or more for the recurrence gate to have enough triples.
- The tool prints each connection timestamp so you can cross-reference
  with the server log and the PCAP.
- A --jitter value of 0.25 is the empirically determined degradation onset;
  above 0.30 detection rate degrades significantly.
"""

import socket
import time
import random
import argparse
from datetime import datetime


def fibonacci_intervals(base, count, jitter=0.0):
    """
    Return a list of `count` inter-connection intervals following the
    Fibonacci additive recurrence starting at `base` seconds.

    If jitter > 0, each interval is multiplied by (1 + U[-jitter, +jitter]).
    """
    if count < 1:
        return []

    # Seed the recurrence with two equal base values.
    # This gives: base, base, 2*base, 3*base, 5*base, 8*base, ...
    a, b = base, base
    intervals = []
    for i in range(count):
        iv = a if i == 0 else (b if i == 1 else None)
        if iv is None:
            # Generate next Fibonacci term
            a, b = b, a + b
            iv = b
        if jitter > 0:
            iv = iv * (1.0 + random.uniform(-jitter, jitter))
            iv = max(iv, 0.1)
        intervals.append(iv)

    # Recalculate properly using the recurrence
    fibs = [base, base]
    while len(fibs) < count:
        fibs.append(fibs[-1] + fibs[-2])

    result = []
    for i, f in enumerate(fibs[:count]):
        iv = f
        if jitter > 0:
            iv = iv * (1.0 + random.uniform(-jitter, jitter))
            iv = max(iv, 0.1)
        result.append(iv)
    return result


def connect_once(host, port, payload):
    """Open a TCP connection, send payload, receive ACK, close."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10.0)
        s.connect((host, port))
        s.sendall(payload.encode())
        s.recv(256)
        s.close()
        return True
    except Exception as e:
        print("  [WARN] Connection error: {}".format(e))
        return False


def run_client(host, port, base, count, jitter, log_file):
    intervals = fibonacci_intervals(base, count, jitter)

    print("=" * 55)
    print("  FIBONACCI BEACON CLIENT")
    print("  Target    : {}:{}".format(host, port))
    print("  Base      : {}s".format(base))
    print("  Count     : {} connections".format(count))
    print("  Jitter    : {:.0%}".format(jitter))
    print("  Start     : {}".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    print()
    print("  Intervals (seconds):")
    print("    " + "  ".join("{:.1f}".format(iv) for iv in intervals))
    print()
    ratios = [intervals[i+1]/intervals[i] for i in range(len(intervals)-1)]
    if ratios:
        print("  Consecutive ratios (should converge to phi=1.618):")
        print("    " + "  ".join("{:.4f}".format(r) for r in ratios))
        print("    mean r_bar = {:.4f}".format(sum(ratios)/len(ratios)))
    print()
    print("  Connecting...")
    print("=" * 55)

    log_lines = []
    t_start = time.time()

    for i, interval in enumerate(intervals):
        # Wait before connecting (except for the very first one)
        if i > 0:
            time.sleep(interval)

        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        t_elapsed = time.time() - t_start
        payload = "beacon:{:03d}:t={:.3f}".format(i + 1, t_elapsed)

        ok = connect_once(host, port, payload)
        status = "OK" if ok else "FAIL"
        line = "  [{}] #{:3d}  elapsed={:8.2f}s  next_wait={:7.2f}s  {}".format(
            ts, i + 1, t_elapsed,
            intervals[i + 1] if i + 1 < len(intervals) else 0.0,
            status,
        )
        print(line)
        log_lines.append(line)

    # Final wait after last connection so capture can pick it up cleanly
    time.sleep(2.0)

    print()
    print("=" * 55)
    print("  Done. {} connections sent.".format(count))
    print("  Total elapsed: {:.1f}s".format(time.time() - t_start))
    print()
    print("  Next steps:")
    print("  1. Stop your packet capture.")
    print("  2. Run: python beacon_hunter.py fib_beacon_validation.pcapng")
    print("=" * 55)

    if log_file:
        try:
            with open(log_file, "w") as f:
                f.write("Fibonacci beacon client log\n")
                f.write("host={} port={} base={}s count={} jitter={}\n".format(
                    host, port, base, count, jitter))
                f.write("\n".join(log_lines) + "\n")
            print("\n  Log saved: {}".format(log_file))
        except Exception as e:
            print("\n  [WARN] Could not write log: {}".format(e))


def main():
    parser = argparse.ArgumentParser(
        description="Fibonacci beacon client for beacon-hunter validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fib_beacon_client.py                        # default: 12 connections, 5s base
  python fib_beacon_client.py --base 10 --count 15  # longer sequence
  python fib_beacon_client.py --jitter 0.10          # 10% timing noise
  python fib_beacon_client.py --log client.log       # save timestamps
        """,
    )
    parser.add_argument("--host",   default="127.0.0.1",
                        help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port",   type=int, default=9999,
                        help="Server port (default: 9999)")
    parser.add_argument("--base",   type=float, default=5.0,
                        help="Base interval in seconds (default: 5.0)")
    parser.add_argument("--count",  type=int, default=12,
                        help="Number of connections to make (default: 12, min: 5)")
    parser.add_argument("--jitter", type=float, default=0.0,
                        help="Timing jitter fraction 0.0-1.0 (default: 0.0)")
    parser.add_argument("--log",    default=None,
                        help="Optional log file path")
    parser.add_argument("--seed",   type=int, default=None,
                        help="Random seed for reproducible jitter (default: None)")
    args = parser.parse_args()

    if args.count < 5:
        print("ERROR: --count must be at least 5 (recurrence gate minimum)")
        return 1
    if not 0.0 <= args.jitter < 1.0:
        print("ERROR: --jitter must be in [0.0, 1.0)")
        return 1
    if args.seed is not None:
        random.seed(args.seed)

    run_client(args.host, args.port, args.base, args.count, args.jitter, args.log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
