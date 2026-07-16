# Ground-Truth Validation — Fibonacci Beacon Capture

This procedure generates a PCAP containing a confirmed Fibonacci-scheduled beacon,
then runs beacon-hunter against it. A successful detection is a confirmed true positive:
you know exactly what's in the capture because you put it there.

---

## What you need

- beacon_hunter.py and detectors.py (in your Downloads folder)
- fib_beacon_client.py and fib_beacon_server.py (in your Downloads folder)
- Wireshark installed
- Two terminal windows

---

## Step 1 — Start Wireshark

Open Wireshark. Start a capture on the **Loopback** interface (called `lo` or
`Loopback Pseudo-Interface 1` on Windows, `lo0` on Mac).

Apply this capture filter to keep the file small:

```
tcp port 9999
```

Leave Wireshark running.

---

## Step 2 — Start the server (Terminal 1)

```
cd Downloads
py fib_beacon_server.py
```

You should see:

```
  FIBONACCI BEACON SERVER
  Listening : 127.0.0.1:9999
  Waiting for beacon client connections...
```

Leave this running.

---

## Step 3 — Start the beacon client (Terminal 2)

For a 1-hour capture with base interval 30 seconds:

```
py fib_beacon_client.py --base 30 --duration 3600
```

The client will print each connection as it happens:

```
  [10:14:05.000] Connection #  1  interval=30.0s  OK
  [10:14:35.000] Connection #  2  interval=30.0s  OK
  [10:15:05.000] Connection #  3  interval=60.0s  OK
  [10:16:05.000] Connection #  4  interval=90.0s  OK
  ...
```

The intervals follow the Fibonacci sequence × base:
  30, 30, 60, 90, 150, 240, 390, 630 ... seconds

After about 8 connections (~37 minutes) the intervals exceed an hour and
the beacon will stop naturally. You can also run a shorter test:

```
py fib_beacon_client.py --base 5 --duration 300
```

This produces connections at 5, 5, 10, 15, 25, 40, 65 ... second intervals
and completes in about 5 minutes with ~7 connections — enough for detection.

---

## Step 4 — Stop and save

When the client finishes (or after enough connections), stop Wireshark and
save the capture as `fib_beacon_validation.pcap` in your Downloads folder.

Stop the server with Ctrl+C.

---

## Step 5 — Run beacon-hunter

```
cd Downloads
py beacon_hunter.py fib_beacon_validation.pcap
```

Expected output for a successful detection:

```
  Flow : 127.0.0.1:<port>->127.0.0.1:9999 (tcp)
    Result      : FIBONACCI_BEACON (score XX%)
    Connections : N
    Ratio r̄     : ~1.54–1.62   Δφ: <0.20   ratio_cv: <0.50   [FIBONACCI]
    Recurrence  : rel_err=<0.20   p=0.000   [FIBONACCI]
```

---

## What the result proves

A FIBONACCI_BEACON detection on this capture is a **confirmed true positive**:
- Ground truth: you ran a Fibonacci-scheduled client
- Detection: beacon-hunter identified the phi-convergent ICI ratios and
  verified the additive recurrence ICI[n+2] ≈ ICI[n+1] + ICI[n]
- The capture contains no other traffic (loopback, filtered to port 9999)

This addresses the open validation gap: sensitivity confirmed on a controlled
lab capture with known ground truth.

---

## Variants worth running

**With jitter** — tests robustness of the recurrence gate:

```
py fib_beacon_client.py --base 30 --duration 3600 --jitter 0.10
```

**Multiple captures** — run with different base intervals to characterize
detection range:

```
py fib_beacon_client.py --base 5  --duration 300   # fast beacon
py fib_beacon_client.py --base 30 --duration 3600  # 30s beacon
py fib_beacon_client.py --base 60 --duration 3600  # slow beacon
```

**Save the reports** — the beacon-hunter report files are your validation
artifacts. Include them with the GitHub repo under `validation/`.

---

## If detection fails

If beacon-hunter does not flag the capture as FIBONACCI_BEACON, check:

1. **Not enough connections.** The recurrence gate needs 8+ connection events.
   With base=30s, you need the capture to run at least ~37 minutes to
   accumulate 8 connections before intervals exceed the session gap.

2. **Session gap too large.** If your Fibonacci intervals are smaller than
   the default 5s session gap, early connections get merged. Lower it:

   ```
   py beacon_hunter.py fib_beacon_validation.pcap --session-gap 2
   ```

3. **Wrong interface in Wireshark.** If you captured on the wrong interface,
   the loopback traffic won't be in the file. Verify the PCAP has packets
   before running the tool.
