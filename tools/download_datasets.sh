#!/bin/bash
# download_datasets.sh
# Run this in WSL2 to download public cybersecurity datasets for validation.
# These are the datasets the paper needs for larger-scale validation.
#
# Usage: bash download_datasets.sh

set -e
DATADIR="$HOME/beacon_validation_data"
mkdir -p "$DATADIR"
cd "$DATADIR"

echo "============================================================"
echo "  DOWNLOADING VALIDATION DATASETS"
echo "  Target: $DATADIR"
echo "============================================================"
echo ""

# ============================================================
# 1. Stratosphere IPS CTU-13 Botnet Dataset (Zeek conn.logs)
# ============================================================
# 13 botnet scenarios with labeled Zeek logs. Multi-hour captures.
# Source: https://www.stratosphereips.org/datasets-ctu13
echo "[1/4] Stratosphere CTU-13 (botnet C2 traffic with Zeek logs)..."
mkdir -p ctu13
cd ctu13

# These are direct download links for the binetflow (labeled) files
# Each scenario is a multi-hour capture with known botnet + background
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13; do
    SCENDIR="scenario_$i"
    mkdir -p "$SCENDIR"
    echo "  Downloading scenario $i..."
    # The binetflow files contain labeled conn records
    wget -q -nc "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/$SCENDIR/detailed-bidirectional-flow-labels/$SCENDIR.binetflow" \
         -O "$SCENDIR/$SCENDIR.binetflow" 2>/dev/null || \
    curl -sL "https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/$SCENDIR/detailed-bidirectional-flow-labels/$SCENDIR.binetflow" \
         -o "$SCENDIR/$SCENDIR.binetflow" 2>/dev/null || \
    echo "    ⚠ Could not download scenario $i (may need manual download)"
done
cd "$DATADIR"
echo "  Done."
echo ""

# ============================================================
# 2. CIC-IDS2017 (5 days of labeled traffic)
# ============================================================
# Monday = benign only. Tue-Fri = various attacks.
# Available on Kaggle and CIC website.
echo "[2/4] CIC-IDS2017..."
echo "  This dataset is ~7GB and requires Kaggle or direct download."
echo "  Option A (Kaggle - requires kaggle CLI):"
echo "    pip install kaggle"
echo "    kaggle datasets download -d cicdataset/cicids2017"
echo ""
echo "  Option B (direct from UNB):"
echo "    wget https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/PCAPs/"
echo ""
echo "  After downloading PCAPs, convert to Zeek conn.logs:"
echo "    for f in *.pcap; do zeek -r \$f; mv conn.log \${f%.pcap}_conn.log; done"
echo ""

# ============================================================
# 3. UWF-ZeekData22 (if not already present)
# ============================================================
echo "[3/4] UWF-ZeekData22..."
if [ -d "$DATADIR/uwf" ]; then
    echo "  Already present at $DATADIR/uwf/"
    ls -la "$DATADIR/uwf/"
else
    echo "  Download from: https://datasets.uwf.edu/"
    echo "  Search for 'ZeekData22'"
    echo "  Extract to $DATADIR/uwf/"
fi
echo ""

# ============================================================
# 4. MAWI Working Group (backbone traffic, multi-day)
# ============================================================
echo "[4/4] MAWI backbone traffic..."
mkdir -p mawi
echo "  MAWI provides daily 15-minute backbone captures."
echo "  Downloading 7 days of recent samplepoints..."
# MAWI samplepoint-F has daily 15-min captures as pcap
for day in 01 02 03 04 05 06 07; do
    echo "  Fetching 2024-01-$day..."
    wget -q -nc "https://mawi.wide.ad.jp/mawi/samplepoint-F/2024/202401${day}1400.pcap.gz" \
         -O "mawi/mawi_2024_01_${day}.pcap.gz" 2>/dev/null || \
    echo "    ⚠ Could not download (may need manual download from mawi.wide.ad.jp)"
done
echo "  After downloading, convert to Zeek:"
echo "    cd mawi && for f in *.pcap.gz; do gunzip \$f && zeek -r \${f%.gz}; mv conn.log \${f%.pcap.gz}_conn.log; done"
echo ""

# ============================================================
# Summary
# ============================================================
echo "============================================================"
echo "  DOWNLOAD SUMMARY"
echo "============================================================"
echo ""
echo "  Data directory: $DATADIR"
echo ""
echo "  For datasets that need manual download:"
echo "  1. CTU-13: https://www.stratosphereips.org/datasets-ctu13"
echo "  2. CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html"
echo "  3. UWF-ZeekData22: https://datasets.uwf.edu/"
echo "  4. MAWI: https://mawi.wide.ad.jp/mawi/"
echo ""
echo "  After downloading PCAPs, convert each to Zeek conn.log:"
echo "    zeek -r capture.pcap"
echo "    mv conn.log capture_conn.log"
echo ""
echo "  Then run all detectors against each conn.log:"
echo "    python3 beacon_hunter.py conn.log"
echo ""
echo "============================================================"
