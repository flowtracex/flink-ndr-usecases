#!/bin/bash

set -e

echo "============================================================"
echo "UC-28: Normalized Identity Impossible Travel"
echo "Straight Demo: Normalize -> Detect"
echo "============================================================"
echo ""

echo "------------------------------------------------------------"
echo "STEP 1: Normalize vendor identity logs"
echo "------------------------------------------------------------"
python3 normalize.py

echo ""
echo "------------------------------------------------------------"
echo "STEP 2: Run one impossible-travel detection"
echo "------------------------------------------------------------"
python3 detect-impossible-travel.py

echo ""
echo "------------------------------------------------------------"
echo "DONE"
echo "------------------------------------------------------------"
echo "Normalized events: normalized-events.json"
echo "Detections: detections.json"
