#!/bin/bash

echo "============================================================"
echo "UC-02: C2 Beaconing Detection"
echo "2-Layer Detection: Flink + Python"
echo "============================================================"
echo ""

# Layer 1: Flink Signal Generation
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "LAYER 1: Flink Signal Generation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# For this demo, we use pre-generated signals
# In production, this would run: python3 ../../shared/run-signals.py layer1-signals/
if [ -f "shared/sample-data.json" ]; then
    cp shared/sample-data.json signals-output.json
    echo "[INFO] Using pre-generated signals from shared/sample-data.json"
    echo "[INFO] Signals ready for correlation"
else
    echo "[ERROR] shared/sample-data.json not found"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "LAYER 2: Python Correlation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run correlation from its directory (fixes path issue)
cd layer2-correlation
python3 correlation.py
CORRELATION_STATUS=$?
cd ..

if [ $CORRELATION_STATUS -ne 0 ]; then
    echo "❌ Layer 2 failed"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ DETECTION COMPLETE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📄 Results saved to: ../../output/c2-detections.db"
echo ""
echo "🔍 Query detections:"
echo "  python3 -c \"import sqlite3; conn = sqlite3.connect('../../output/c2-detections.db'); cursor = conn.cursor(); rows = cursor.execute('SELECT detection_id, detection_type, src_ip, dest_ip, severity FROM c2_detections').fetchall(); [print(f'ID: {r[0]}, Type: {r[1]}, {r[2]} → {r[3]}, Severity: {r[4]}') for r in rows]; conn.close()\""
echo ""

