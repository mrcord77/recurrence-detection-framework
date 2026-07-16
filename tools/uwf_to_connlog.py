#!/usr/bin/env python3
"""
uwf_to_connlog.py
-----------------
Converts UWF-ZeekData22 / UWF-ZeekDataFall22 parquet or CSV files to
Zeek conn.log tab-separated format compatible with beacon_hunter.py.

Usage:
    pip install pandas pyarrow
    
    # From a single parquet file:
    python uwf_to_connlog.py --input conn.parquet --output conn.log
    
    # From a directory of parquet files (combines them):
    python uwf_to_connlog.py --input ~/uwf_data/ --output uwf_combined.log
    
    # Then run Beacon Hunter on the result:
    python beacon_hunter.py uwf_combined.log

UWF column mapping to Zeek conn.log fields:
    ts          -> timestamp
    id.orig_h   -> source IP
    id.orig_p   -> source port
    id.resp_h   -> destination IP
    id.resp_p   -> destination port
    proto       -> protocol
    duration    -> duration
    orig_bytes  -> bytes sent
    resp_bytes  -> bytes received
    label       -> MITRE ATT&CK label (written to a separate column for reference)
"""

import sys
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


def load_parquet(path):
    try:
        import pandas as pd
        return pd.read_parquet(path)
    except ImportError:
        log.error("pyarrow not installed. Run: pip install pyarrow pandas")
        sys.exit(1)


def load_csv(path):
    import pandas as pd
    return pd.read_csv(path, low_memory=False)


def load_file(path):
    path = Path(path)
    if path.suffix == ".parquet":
        return load_parquet(path)
    elif path.suffix in (".csv", ".tsv", ".log"):
        return load_csv(path)
    else:
        log.warning(f"Unknown extension {path.suffix}, trying CSV")
        return load_csv(path)


def detect_columns(df):
    """Map UWF column names to standard Zeek field names."""
    cols = set(df.columns.str.lower())
    
    # UWF-ZeekData22 uses standard Zeek field names but may vary
    mappings = {
        "ts":           ["ts", "timestamp", "time", "start_time", "datetime"],
        "id.orig_h":    ["src_ip_zeek", "id.orig_h", "id_orig_h", "src_ip", "source_ip", "orig_h"],
        "id.orig_p":    ["src_port_zeek", "id.orig_p", "id_orig_p", "src_port", "source_port", "orig_p"],
        "id.resp_h":    ["dest_ip_zeek", "id.resp_h", "id_resp_h", "dst_ip", "dest_ip", "resp_h"],
        "id.resp_p":    ["dest_port_zeek", "id.resp_p", "id_resp_p", "dst_port", "dest_port", "resp_p"],
        "proto":        ["proto", "protocol"],
        "service":      ["service"],
        "duration":     ["duration"],
        "orig_bytes":   ["orig_bytes", "bytes_sent", "src_bytes"],
        "resp_bytes":   ["resp_bytes", "bytes_recv", "dst_bytes"],
        "label":        ["label_tactic", "label", "attack_cat", "mitre_label", "tactic",
                         "class", "detailed_label", "Label", "Attack"],
    }
    
    col_map = {}
    for target, candidates in mappings.items():
        for cand in candidates:
            if cand in cols:
                actual = [c for c in df.columns if c.lower() == cand][0]
                col_map[target] = actual
                break
    
    required = ["ts", "id.orig_h", "id.resp_h"]
    missing = [r for r in required if r not in col_map]
    if missing:
        log.error(f"Could not find required columns: {missing}")
        log.error(f"Available columns: {list(df.columns[:20])}")
        sys.exit(1)
    
    return col_map


ZEEK_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes",
    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents",
]


def convert(input_path, output_path, max_rows=None, label_col=None):
    import pandas as pd
    import numpy as np

    input_path = Path(input_path)
    output_path = Path(output_path)

    # Load -- handle directory of files
    if input_path.is_dir():
        files = sorted(input_path.glob("**/*.parquet")) + \
                sorted(input_path.glob("**/*.csv"))
        if not files:
            log.error(f"No parquet or CSV files found in {input_path}")
            sys.exit(1)
        log.info(f"Loading {len(files)} files from {input_path}")
        dfs = []
        for f in files:
            log.info(f"  Loading {f.name}")
            dfs.append(load_file(f))
        df = pd.concat(dfs, ignore_index=True)
    else:
        log.info(f"Loading {input_path}")
        df = load_file(input_path)

    if max_rows:
        df = df.head(max_rows)

    log.info(f"Loaded {len(df):,} rows, {len(df.columns)} columns")
    log.info(f"Columns: {list(df.columns[:15])}" + 
             (f"... (+{len(df.columns)-15} more)" if len(df.columns) > 15 else ""))

    col_map = detect_columns(df)
    log.info(f"Column mapping: {col_map}")

    # Label summary
    if "label" in col_map:
        label_col = col_map["label"]
        label_counts = df[label_col].value_counts()
        log.info(f"Label distribution (top 10):")
        for label, count in label_counts.head(10).items():
            log.info(f"  {str(label):<40} {count:>8,}")

    # Build output dataframe
    out = pd.DataFrame()
    
    # Timestamp -- ensure float
    ts_col = col_map["ts"]
    try:
        ts_series = pd.to_numeric(df[ts_col], errors="coerce")
        if ts_series.isna().mean() > 0.5:
            raise ValueError("mostly NaN -- try datetime parse")
        out["ts"] = ts_series
    except Exception:
        # Try parsing as datetime string (UWF uses ISO format in some files)
        parsed = pd.to_datetime(df[ts_col], errors="coerce", infer_datetime_format=True)
        out["ts"] = parsed.astype("int64") / 1e9
        out["ts"] = out["ts"].where(out["ts"] > 0, other=pd.NA)
    
    out["uid"]      = "Cx" + df.index.astype(str)
    out["id.orig_h"] = df[col_map["id.orig_h"]].fillna("-")
    out["id.orig_p"] = df.get(col_map.get("id.orig_p", ""), pd.Series(["-"]*len(df))).fillna("-")
    out["id.resp_h"] = df[col_map["id.resp_h"]].fillna("-")
    out["id.resp_p"] = df.get(col_map.get("id.resp_p", ""), pd.Series(["-"]*len(df))).fillna("-")
    out["proto"]     = df.get(col_map.get("proto", ""), pd.Series(["tcp"]*len(df))).fillna("tcp")
    out["service"]   = df.get(col_map.get("service", ""), pd.Series(["-"]*len(df))).fillna("-")
    out["duration"]  = df.get(col_map.get("duration", ""), pd.Series(["-"]*len(df))).fillna("-")
    out["orig_bytes"] = df.get(col_map.get("orig_bytes", ""), pd.Series(["-"]*len(df))).fillna("-")
    out["resp_bytes"] = df.get(col_map.get("resp_bytes", ""), pd.Series(["-"]*len(df))).fillna("-")
    
    # Fill remaining standard Zeek fields with placeholder
    for field in ZEEK_FIELDS:
        if field not in out.columns:
            out[field] = "-"

    # Drop rows with missing timestamps
    out = out.dropna(subset=["ts"])
    out = out[out["ts"] > 0]
    out = out.sort_values("ts").reset_index(drop=True)
    
    log.info(f"Writing {len(out):,} rows to {output_path}")

    with open(output_path, "w") as f:
        # Zeek conn.log header
        f.write("#separator \\x09\n")
        f.write("#set_separator ,\n")
        f.write("#empty_field (empty)\n")
        f.write("#unset_field -\n")
        f.write(f"#path conn\n")
        f.write(f"#fields\t" + "\t".join(ZEEK_FIELDS) + "\n")
        f.write(f"#types\t" + "\t".join(["time"] + ["string"]*(len(ZEEK_FIELDS)-1)) + "\n")
        
        # Write rows
        for row in out[ZEEK_FIELDS].itertuples(index=False):
            f.write("\t".join(str(v) for v in row) + "\n")
    
    log.info(f"Done. Run: python beacon_hunter.py {output_path}")
    
    # Write label index if available
    if "label" in col_map:
        label_path = output_path.with_suffix(".labels.csv")
        out["label"] = df[col_map["label"]].fillna("benign").values[:len(out)]
        out[["ts", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "label"]].to_csv(
            label_path, index=False)
        log.info(f"Label index written: {label_path}")
        log.info("You can cross-reference Beacon Hunter flags against this file.")

    return len(out)


def main():
    parser = argparse.ArgumentParser(
        description="Convert UWF-ZeekData22 parquet/CSV to Zeek conn.log for Beacon Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python uwf_to_connlog.py --input conn.parquet --output conn.log
  python uwf_to_connlog.py --input ~/uwf_data/ --output uwf_combined.log
  python uwf_to_connlog.py --input ~/uwf_data/ --output uwf_combined.log --max-rows 500000
        """
    )
    parser.add_argument("--input",    required=True,  help="Input parquet/CSV file or directory")
    parser.add_argument("--output",   required=True,  help="Output Zeek conn.log path")
    parser.add_argument("--max-rows", type=int,       help="Limit rows (for testing)")
    args = parser.parse_args()

    n = convert(args.input, args.output, args.max_rows)
    print(f"\nConverted {n:,} connections -> {args.output}")
    print(f"Next: python beacon_hunter.py {args.output}")


if __name__ == "__main__":
    main()
