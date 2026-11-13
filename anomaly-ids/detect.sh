#!/bin/bash
# Runs the full batch pipeline. Same as: anomaly-detect run
set -e
cd "$(dirname "$0")"
python3 -m anomaly_detector.cli run "$@"
