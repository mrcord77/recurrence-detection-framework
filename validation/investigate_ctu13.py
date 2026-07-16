#!/usr/bin/env python3
"""
investigate_ctu13.py
--------------------
Deep investigation of CTU-13 results:
1. What are the 146 botnet structural detections?
2. Flow-level FPR (distinct flows flagged, not classifications)
3. Per-detector confusion matrices

Runs on scenario 1 and 9 (highest botnet detection counts) + one small scenario.
"""

import os, sys, importlib, time
from datetime import datetime
from collections import defaultdict

# ============================================================
# REPO-RELATIVE SETUP
# ============================================================

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

DETECTOR_FOLDERS = [
    ("Beacon Hunter",     "beacon_hunter"),
    ("Tribonacci Hunter", "tribonacci_hunter"),
    ("Padovan Hunter",    "padovan_hunter"),
    ("Narayana Hunter",   "narayana_hunter"),
    ("Reverse Scanner",   "reverse_scanner"),
    ("Bounded Hunter",    "bounded_hunter"),
]

CTU13_DIR = os.path.expanduser("~/beacon_validation_data/CTU-13-Dataset")

def load_detectors():
    dets = []
    for name, folder in DETECTOR_FOLDERS:
        try:
            mod = importlib.import_module(f"detectors.{folder}.detectors")
            dets.append((name, mod))
        except Exception:
            pass
    return dets

def parse_binetflow(filepath):
    flows = defaultdict(lambda: {'timestamps':[],'label':'','proto':'','dport':''})
    with open(filepath,'r',errors='replace') as f:
        header=None
        for line in f:
            row=line.strip().split(',')
            if not row: continue
            if row[0].strip().startswith('StartTime'): header=row; continue
            if header is None or len(row)<15: continue
            try:
                ts=datetime.strptime(row[0].strip()[:23],'%Y/%m/%d %H:%M:%S.%f').timestamp()
                src=row[3].strip(); dst=row[6].strip(); dport=row[7].strip()
                proto=row[2].strip()
                key=(src,dst,dport)
                flows[key]['timestamps'].append(ts)
                flows[key]['label']=row[-1].strip()
                flows[key]['proto']=proto
                flows[key]['dport']=dport
            except: continue
    for k in flows: flows[k]['timestamps'].sort()
    return dict(flows)

def classify(dm, timestamps):
    try:
        r=dm.classify_flow(list(timestamps),connection_level=True)
        c=r.get('classification','UNKNOWN')
        conf=r.get('confidence',0)
        if c in ('BACKGROUND','INSUFFICIENT_DATA','UNKNOWN'): return 'clean',c,conf
        if 'REGULAR_BEACON' in c or 'JITTERED_BEACON' in c: return 'periodic',c,conf
        if 'NON_PHYSICAL' in c: return 'non_physical',c,conf
        return 'structural',c,conf
    except: return 'error','',0

# ============================================================
# MAIN
# ============================================================

dets = load_detectors()
print(f"Loaded {len(dets)} detectors")
print()

# Process scenarios with botnet detections
# From screenshots: scenario 1 had 14 botnet, 8 had 69, 9 had 42+107
scenarios = ['1', '8', '9']

for scenario in scenarios:
    sdir = os.path.join(CTU13_DIR, scenario)
    if not os.path.isdir(sdir):
        print(f"Scenario {scenario} not found")
        continue

    for fname in sorted(os.listdir(sdir)):
        if not fname.endswith('.binetflow'): continue
        print(f"{'='*70}")
        print(f"SCENARIO {scenario}: {fname}")
        print(f"{'='*70}")
        t0 = time.time()

        flows = parse_binetflow(os.path.join(sdir, fname))
        qual = {k:v for k,v in flows.items() if len(v['timestamps'])>=6}
        bg = {k:v for k,v in qual.items() if 'Background' in v['label'] or 'Normal' in v['label']}
        bot = {k:v for k,v in qual.items() if 'Botnet' in v['label']}
        print(f"Qualifying flows: {len(qual)} ({len(bg)} background, {len(bot)} botnet)")
        print()

        # ============================================================
        # INVESTIGATE BOTNET DETECTIONS
        # ============================================================
        print("--- BOTNET FLOW DETECTIONS ---")
        bot_details = []
        for key, flow in bot.items():
            src, dst, dport = key
            flow_flags = []
            for dn, dm in dets:
                status, cls, conf = classify(dm, flow['timestamps'])
                if status == 'structural':
                    flow_flags.append((dn, cls, conf))

            if flow_flags:
                n = len(flow['timestamps'])
                icis = [flow['timestamps'][i+1]-flow['timestamps'][i] for i in range(min(8, n-1))]
                ici_str = ", ".join([f"{x:.1f}" for x in icis[:6]])
                duration = flow['timestamps'][-1] - flow['timestamps'][0]
                print(f"  {src} -> {dst}:{dport} | n={n} | dur={duration:.0f}s | label={flow['label']}")
                print(f"    ICIs (first 6): [{ici_str}]")
                for dn, cls, conf in flow_flags:
                    print(f"    -> {dn}: {cls} (conf={conf:.2f})")
                print()
                bot_details.append({
                    'key': key, 'n': n, 'flags': flow_flags,
                    'label': flow['label'], 'duration': duration
                })

        if not bot_details:
            print("  No structural detections on botnet flows.")
        print()

        # ============================================================
        # FLOW-LEVEL FPR (distinct flows, not classifications)
        # ============================================================
        print("--- FLOW-LEVEL FALSE POSITIVE ANALYSIS ---")
        bg_flow_flagged = set()  # distinct flows flagged by ANY detector
        bg_flow_flags_by_det = defaultdict(set)  # flows flagged per detector
        bg_flags_by_type = defaultdict(int)
        bg_flow_flag_details = defaultdict(list)  # what each flagged flow was called

        for key, flow in bg.items():
            for dn, dm in dets:
                status, cls, conf = classify(dm, flow['timestamps'])
                if status == 'structural':
                    bg_flow_flagged.add(key)
                    bg_flow_flags_by_det[dn].add(key)
                    bg_flags_by_type[cls] += 1
                    bg_flow_flag_details[key].append((dn, cls))

        n_bg = len(bg)
        n_flagged = len(bg_flow_flagged)
        flow_fpr = n_flagged / n_bg * 100 if n_bg > 0 else 0
        print(f"  Background flows: {n_bg}")
        print(f"  Distinct flows flagged: {n_flagged} ({flow_fpr:.2f}%)")
        print()

        # Excluding prime
        bg_flow_flagged_no_prime = set()
        for key, flags in bg_flow_flag_details.items():
            non_prime = [f for f in flags if 'PRIME' not in f[1]]
            if non_prime:
                bg_flow_flagged_no_prime.add(key)
        n_flagged_no_prime = len(bg_flow_flagged_no_prime)
        fpr_no_prime = n_flagged_no_prime / n_bg * 100 if n_bg > 0 else 0
        print(f"  Distinct flows flagged (excl prime): {n_flagged_no_prime} ({fpr_no_prime:.2f}%)")
        print()

        print(f"  Per-detector flow-level flags:")
        for dn, _ in dets:
            n_det = len(bg_flow_flags_by_det.get(dn, set()))
            rate = n_det / n_bg * 100 if n_bg > 0 else 0
            if n_det > 0:
                print(f"    {dn:25s}: {n_det:>5d} flows ({rate:.2f}%)")

        print()

        # Show n-value distribution of flagged flows
        n_values = [len(bg[k]['timestamps']) for k in bg_flow_flagged]
        if n_values:
            import numpy as np
            print(f"  Flow length distribution of flagged flows:")
            print(f"    min={min(n_values)}, median={sorted(n_values)[len(n_values)//2]}, max={max(n_values)}, mean={sum(n_values)/len(n_values):.1f}")
            short = sum(1 for n in n_values if n <= 8)
            print(f"    n<=8: {short}/{len(n_values)} ({short/len(n_values)*100:.0f}%)")
            print()

        elapsed = time.time() - t0
        print(f"  Time: {elapsed:.1f}s")
        print()
