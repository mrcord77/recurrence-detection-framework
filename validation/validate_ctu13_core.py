#!/usr/bin/env python3
"""
validate_ctu13_n8_core.py
-------------------------
OPTION A: Individual recurrence detectors + Bounded (no Reverse Scanner).
Forward detection only. n>=8 minimum window.
"""

import os
import sys
import csv
import importlib
import time
from datetime import datetime
from collections import defaultdict

# ============================================================
# CONFIGURATION
# ============================================================

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

CTU13_DIR = os.path.expanduser("~/beacon_validation_data/CTU-13-Dataset/CTU-13-Dataset")
STRATOSPHERE_DIR = os.path.expanduser("~/beacon_validation_data/stratosphere")

# Detector folders under detectors/
DETECTOR_FOLDERS = [
    ("Beacon Hunter",     "beacon_hunter"),
    ("Tribonacci Hunter", "tribonacci_hunter"),
    ("Padovan Hunter",    "padovan_hunter"),
    ("Narayana Hunter",   "narayana_hunter"),
    ("Bounded Hunter",    "bounded_hunter"),
]

MIN_TIMESTAMPS = 8  # Minimum connections per flow to test (raised from 6)


# ============================================================
# BINETFLOW PARSER
# ============================================================

def parse_binetflow(filepath):
    """
    Parse a binetflow file and group connections into flows.

    Groups by (SrcAddr, DstAddr, Dport) and collects timestamps.
    Returns dict: flow_key -> {"timestamps": [...], "label": str, "proto": str}
    """
    flows = defaultdict(lambda: {"timestamps": [], "label": "", "proto": ""})

    with open(filepath, "r", errors="replace") as f:
        reader = csv.reader(f)
        header = None
        for row in reader:
            if not row:
                continue
            # Header line
            if row[0].strip().startswith("StartTime"):
                header = [h.strip() for h in row]
                continue
            if header is None:
                continue
            if len(row) < len(header):
                continue

            try:
                start_time_str = row[0].strip()
                src_addr = row[3].strip()
                dst_addr = row[6].strip()
                dport = row[7].strip()
                proto = row[2].strip()
                label = row[-1].strip() if len(row) > 14 else ""

                # Parse timestamp: "2011/08/10 09:46:53.047277"
                ts = datetime.strptime(start_time_str[:23], "%Y/%m/%d %H:%M:%S.%f")
                epoch = ts.timestamp()

                key = (src_addr, dst_addr, dport)
                flows[key]["timestamps"].append(epoch)
                flows[key]["proto"] = proto
                if label:
                    flows[key]["label"] = label

            except (ValueError, IndexError):
                continue

    # Sort timestamps within each flow
    for key in flows:
        flows[key]["timestamps"].sort()

    return dict(flows)


# ============================================================
# DETECTOR LOADING
# ============================================================

def load_detectors():
    """Load all detectors, return list of (name, module)."""
    detectors = []
    for name, folder in DETECTOR_FOLDERS:
        try:
            mod = importlib.import_module(f"detectors.{folder}.detectors")
            detectors.append((name, mod))
            print(f"  [OK] Loaded {name}")
        except Exception as e:
            print(f"  [FAIL] {name}: {e}")
    return detectors


def classify(det_mod, timestamps):
    """Run classify_flow, return (status, detail)."""
    try:
        r = det_mod.classify_flow(list(timestamps), connection_level=True, min_pkts=7)
        cls = r.get("classification", "UNKNOWN")
        if cls in ("BACKGROUND", "INSUFFICIENT_DATA", "UNKNOWN"):
            return ("clean", cls)
        if "REGULAR_BEACON" in cls or "JITTERED_BEACON" in cls:
            return ("periodic", cls)
        if "NON_PHYSICAL" in cls:
            return ("non_physical", cls)
        return ("structural", cls)
    except Exception as e:
        return ("error", str(e))


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  CTU-13 + STRATOSPHERE VALIDATION")
    print("  Testing detectors against real labeled network traffic")
    print("=" * 70)
    print()

    # Load detectors
    detectors = load_detectors()
    if not detectors:
        print("No detectors loaded. Check DETECTOR_FOLDERS.")
        sys.exit(1)
    print()

    # Find all binetflow files
    binetflow_files = []

    # CTU-13 scenarios
    if os.path.isdir(CTU13_DIR):
        for scenario in sorted(os.listdir(CTU13_DIR)):
            scenario_dir = os.path.join(CTU13_DIR, scenario)
            if not os.path.isdir(scenario_dir):
                continue
            for fname in os.listdir(scenario_dir):
                if fname.endswith(".binetflow"):
                    binetflow_files.append((f"CTU13-{scenario}", os.path.join(scenario_dir, fname)))
    else:
        print(f"  [WARN] CTU-13 not found at {CTU13_DIR}")

    # Stratosphere captures
    if os.path.isdir(STRATOSPHERE_DIR):
        for fname in sorted(os.listdir(STRATOSPHERE_DIR)):
            if fname.endswith(".binetflow"):
                binetflow_files.append((f"Strat-{fname[:10]}", os.path.join(STRATOSPHERE_DIR, fname)))
    else:
        print(f"  [WARN] Stratosphere not found at {STRATOSPHERE_DIR}")

    if not binetflow_files:
        print("No binetflow files found.")
        sys.exit(1)

    print(f"Found {len(binetflow_files)} binetflow files to process.")
    print()

    # Process each file
    total_background_flows = 0
    total_botnet_flows = 0
    total_structural_fp = 0
    total_nonphysical_fp = 0
    total_periodic_flags = 0
    total_botnet_flags = 0
    structural_fp_details = []
    structural_fp_by_type = defaultdict(int)

    for dataset_name, filepath in binetflow_files:
        print(f"Processing: {dataset_name} ({os.path.basename(filepath)})...")
        start = time.time()

        # Parse flows
        flows = parse_binetflow(filepath)

        # Filter to flows with enough timestamps
        qualifying = {k: v for k, v in flows.items()
                      if len(v["timestamps"]) >= MIN_TIMESTAMPS}

        # Split by label
        background_flows = {k: v for k, v in qualifying.items()
                           if "Background" in v["label"] or "Normal" in v["label"]}
        botnet_flows = {k: v for k, v in qualifying.items()
                       if "Botnet" in v["label"] or "Malware" in v["label"]
                       or "CC" in v["label"] or "C&C" in v["label"]}
        other_flows = {k: v for k, v in qualifying.items()
                      if k not in background_flows and k not in botnet_flows}

        n_bg = len(background_flows)
        n_bot = len(botnet_flows)
        n_other = len(other_flows)
        total_background_flows += n_bg
        total_botnet_flows += n_bot

        print(f"  Flows: {len(qualifying)} qualifying ({n_bg} background, {n_bot} botnet, {n_other} other)")

        if n_bg == 0 and n_bot == 0:
            print(f"  Skipping (no labeled flows with {MIN_TIMESTAMPS}+ connections)")
            print()
            continue

        # Test background flows (looking for FALSE POSITIVES)
        bg_structural = 0
        bg_nonphysical = 0
        bg_periodic = 0
        for key, flow_data in background_flows.items():
            for det_name, det_mod in detectors:
                status, cls = classify(det_mod, flow_data["timestamps"])
                if status == "structural":
                    bg_structural += 1
                    total_structural_fp += 1
                    structural_fp_by_type[f"{det_name}|{cls}"] += 1
                    if len(structural_fp_details) < 20:
                        src, dst, dport = key
                        structural_fp_details.append(
                            f"  {dataset_name} | {det_name} | {src}->{dst}:{dport} | "
                            f"{cls} | n={len(flow_data['timestamps'])} | {flow_data['label']}")
                elif status == "non_physical":
                    bg_nonphysical += 1
                    total_nonphysical_fp += 1
                elif status == "periodic":
                    bg_periodic += 1
                    total_periodic_flags += 1

        # Test botnet flows (looking for DETECTIONS — not FP)
        bot_structural = 0
        for key, flow_data in botnet_flows.items():
            for det_name, det_mod in detectors:
                status, cls = classify(det_mod, flow_data["timestamps"])
                if status == "structural":
                    bot_structural += 1
                    total_botnet_flags += 1

        elapsed = time.time() - start
        print(f"  Background: {bg_structural} structural, {bg_nonphysical} non-physical, {bg_periodic} periodic")
        if n_bot > 0:
            print(f"  Botnet:     {bot_structural} structural flags")
        print(f"  Time: {elapsed:.1f}s")
        print()

    # ============================================================
    # SUMMARY
    # ============================================================
    print("=" * 70)
    print("  RESULTS SUMMARY")
    print("=" * 70)
    print()
    print(f"  Datasets processed:        {len(binetflow_files)}")
    print(f"  Background flows tested:   {total_background_flows}")
    print(f"  Botnet flows tested:       {total_botnet_flows}")
    print(f"  Detectors:                 {len(detectors)}")
    print(f"  Total classifications:     {(total_background_flows + total_botnet_flows) * len(detectors)}")
    print()
    print(f"  STRUCTURAL FP ON BACKGROUND:    {total_structural_fp}")
    print(f"  NON_PHYSICAL on background:     {total_nonphysical_fp}  (variance flag, not structural)")
    print(f"  Periodic flags on background:   {total_periodic_flags}")
    print(f"  Structural flags on botnet:     {total_botnet_flags}")
    print()

    if total_background_flows > 0 and len(detectors) > 0:
        total_bg_tests = total_background_flows * len(detectors)
        fpr_structural = total_structural_fp / total_bg_tests * 100
        fpr_including_np = (total_structural_fp + total_nonphysical_fp) / total_bg_tests * 100
        print(f"  Structural FPR (excl NON_PHYSICAL): {total_structural_fp}/{total_bg_tests} = {fpr_structural:.4f}%")
        print(f"  Structural FPR (incl NON_PHYSICAL): {total_structural_fp + total_nonphysical_fp}/{total_bg_tests} = {fpr_including_np:.4f}%")
    print()

    if structural_fp_by_type:
        print("  BREAKDOWN BY DETECTOR AND CLASSIFICATION:")
        for key in sorted(structural_fp_by_type, key=lambda k: -structural_fp_by_type[k]):
            det, cls = key.split("|")
            print(f"    {det:25s} {cls:35s} {structural_fp_by_type[key]:>6d}")
        print()

    if structural_fp_details:
        print("  STRUCTURAL FALSE POSITIVE DETAILS (first 20):")
        for d in structural_fp_details:
            print(d)
        print()

    if total_structural_fp == 0:
        print("  [PASS] ZERO structural false positives on real labeled background traffic.")
        print("  This result can be added to the paper.")
    else:
        print(f"  [WARN] {total_structural_fp} structural false positive(s) on background traffic.")
        print("  Investigate before adding to the paper.")
    print()
