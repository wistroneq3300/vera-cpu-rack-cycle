#!/bin/bash
# Stop any running neutrin_cycle.py / dryrun_sim.py campaign.
# Usage: ./stop_cycle.sh

echo "Stopping neutrin_cycle.py ..."
pkill -9 -f neutrin_cycle.py
pkill -9 -f dryrun_sim.py
sleep 2

left=$(pgrep -af neutrin_cycle.py)
if [ -n "$left" ]; then
    echo "STILL RUNNING:"
    echo "$left"
    exit 1
fi

echo "All campaign processes stopped."
