#!/bin/bash

# Define the session name
SESSION_NAME="encryption-session"

# Define the path to the src and vaults directories
SRC_DIR="$(pwd)/src"
VAULTS_DIR="$(pwd)/vaults"

# Check if the vaults directory exists, if not, create it
if [ ! -d "$VAULTS_DIR" ]; then
    mkdir "$VAULTS_DIR"
fi

# Start a new tmux session in detached mode
tmux new-session -d -s "$SESSION_NAME"

# Send the command to change to the src directory and run the Python script
tmux send-keys -t "$SESSION_NAME" "cd $SRC_DIR" C-m
tmux send-keys -t "$SESSION_NAME" "python3 main.py" C-m

# Attach to the tmux session
tmux attach-session -t "$SESSION_NAME"

# After the user exits the Python script and types 'exit', the following lines will execute
# Kill the tmux session to ensure it's not just detached
tmux kill-session -t "$SESSION_NAME"
