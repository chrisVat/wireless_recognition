#!/bin/bash

# Read the PID of the recording process
pid=$(cat recording_pid.txt)

# Stop the recording
kill $pid

# Get the current time in milliseconds
stop_time=$(date +%s%3N)

echo "Recording stopped at: $stop_time ms"
