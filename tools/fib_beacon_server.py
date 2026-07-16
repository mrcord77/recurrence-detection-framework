"""
fib_beacon_server.py
--------------------
Minimal TCP server for Fibonacci beacon validation.

Accepts connections from fib_beacon_client.py and logs each one with a
timestamp. Run this in one terminal, the client in another, and Wireshark
capturing on the loopback interface (or whichever interface you use).

Usage
-----
  py fib_beacon_server.py                  # default port 9999
  py fib_beacon_server.py --port 9999
  py fib_beacon_server.py --log beacon_server.log

The server logs each connection timestamp to stdout and optionally to a
log file. Cross-reference these timestamps with the client output and the
Wireshark capture to verify the Fibonacci schedule end-to-end.
"""

import socket
import threading
import time
import argparse
from datetime import datetime


def handle_connection(conn, addr, log_file, connection_count, lock):
    try:
        data = conn.recv(256)
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        conn.sendall(b"ACK")
        conn.close()

        with lock:
            connection_count[0] += 1
            n = connection_count[0]
            line = "  [{}] Connection #{:3d} from {}:{}  payload={}".format(
                ts, n, addr[0], addr[1], data.decode(errors="replace").strip())
            print(line)
            if log_file:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
    except Exception as e:
        print("  Handler error: {}".format(e))


def run_server(host, port, log_file):
    connection_count = [0]
    lock = threading.Lock()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(32)
    server.settimeout(1.0)

    print("=" * 55)
    print("  FIBONACCI BEACON SERVER")
    print("  Listening : {}:{}".format(host, port))
    print("  Start     : {}".format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    if log_file:
        print("  Log file  : {}".format(log_file))
    print()
    print("  Waiting for beacon client connections...")
    print("  Ctrl+C to stop.")
    print("=" * 55)
    print()

    try:
        while True:
            try:
                conn, addr = server.accept()
                t = threading.Thread(
                    target=handle_connection,
                    args=(conn, addr, log_file, connection_count, lock),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print()
        print("=" * 55)
        print("  Server stopped.")
        print("  Total connections received: {}".format(connection_count[0]))
        print("=" * 55)
    finally:
        server.close()


def main():
    parser = argparse.ArgumentParser(
        description="Fibonacci beacon server for beacon-hunter validation"
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9999,
                        help="Bind port (default: 9999)")
    parser.add_argument("--log", default=None,
                        help="Optional log file path")
    args = parser.parse_args()

    run_server(args.host, args.port, args.log)


if __name__ == "__main__":
    main()
