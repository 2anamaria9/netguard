#!/bin/bash

TARGET=$1
PORTS=$2

echo "[attack-lab] Starting port scan against $TARGET (ports $PORTS)"
echo "[attack-lab] Timestamp: $(date '+%H:%M:%S')"

nmap -p $PORTS $TARGET

echo "[attack-lab] Scan finished at $(date '+%H:%M:%S')"