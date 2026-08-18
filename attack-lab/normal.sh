#!/bin/bash

DURATION=$1

echo "[attack-lab] Starting normal-traffic baseline for ${DURATION}s"
echo "[attack-lab] Timestamp: $(date '+%H:%M:%S')"

SITES=(
    "https://example.com"
    "https://www.wikipedia.org"
    "https://www.python.org"
    "https://httpbin.org/get"
    "https://www.gnu.org"
)

end=$((SECONDS + DURATION))
while [ $SECONDS -lt $end ]; do
    site="${SITES[$RANDOM % ${#SITES[@]}]}"
    curl -s $site -o /dev/null --max-time 5
    sleep 2
done

echo "[attack-lab] Baseline finished at $(date '+%H:%M:%S')"