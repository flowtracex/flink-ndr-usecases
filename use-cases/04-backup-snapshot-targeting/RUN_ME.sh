#!/bin/bash

echo "============================================================"
echo "UC-04: Backup / Snapshot Targeting Detection"
echo "2-Layer Detection: Flink + Python"
echo "============================================================"
echo ""

echo "------------------------------------------------------------"
echo "LAYER 1: Flink Signal Generation"
echo "------------------------------------------------------------"
echo ""

python3 ../../shared/run-signals.py layer1-signals/

if [ $? -ne 0 ]; then
    echo "Layer 1 failed"
    exit 1
fi

echo ""
echo "------------------------------------------------------------"
echo "LAYER 2: Python Correlation"
echo "------------------------------------------------------------"
echo ""

cd layer2-correlation
python3 correlation.py
CORRELATION_STATUS=$?
cd ..

if [ $CORRELATION_STATUS -ne 0 ]; then
    echo "Layer 2 failed"
    exit 1
fi

echo ""
echo "------------------------------------------------------------"
echo "DETECTION COMPLETE"
echo "------------------------------------------------------------"
echo ""
echo "Results saved to: ../../output/ransomware-detections.db"
echo ""
echo "Query detections:"
echo "  sqlite3 ../../output/ransomware-detections.db 'SELECT detection_id, detection_type, src_ip, severity FROM ransomware_detections;'"
echo ""
