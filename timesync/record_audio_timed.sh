#!/bin/bash

# Get the current time in milliseconds
start_time=$(date +%Y%m%d_%H%M%S_%3N)

# Start the audio recording with the plug plugin
arecord -f S16_LE -r 44100 -c 2 -D plug:default "output_${start_time}.wav" &

# Save the process ID of the recording
echo $! > recording_pid.txt

echo "Recording started at: $start_time ms"
