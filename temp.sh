#!/bin/bash

# Step 1: Change to the traces directory
cd ./ChampSim_CRC2/trace || { echo "Directory ./trace not found."; exit 1; }

# Step 2: Create the destination directory if it doesn't exist
mkdir -p ../traces_gz

# Step 3: Convert each .trace.xz file to .trace.gz and move it
for file in *.trace.xz; do
    if [[ -f "$file" ]]; then
        base_name="${file%.xz}"  # Remove .xz extension
        echo "Converting $file to $base_name.gz..."
        
        # Convert .xz to .gz using streaming to avoid temp storage
        xz -dck "$file" | gzip > "../traces_gz/${base_name}.gz"
    fi
done

echo "All .trace.xz files converted and moved to ../traces_gz/"
