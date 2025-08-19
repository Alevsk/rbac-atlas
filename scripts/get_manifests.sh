#!/usr/bin/env bash

# This script analyzes Helm charts to generate JSON manifests.
# It iterates through each chart directory, checks for a custom-values.yaml,
# and runs rbac-scope to produce a JSON output file.

# Best Practice: Exit immediately if a command exits with a non-zero status.
# -e: exit on error
# -u: treat unset variables as an error
# -o pipefail: the return value of a pipeline is the status of the last command to exit with a non-zero status
set -euo pipefail

# Ensure the output directory exists
mkdir -p manifests

echo "INFO: Analyzing charts in the 'charts/' directory..."

for chart_dir in charts/*/; do
    # Ensure it's a directory before processing
    if [[ ! -d "$chart_dir" ]]; then
        continue
    fi

    # Extract the chart name from the directory path
    # e.g., "charts/my-chart/" becomes "my-chart"
    chart_name=$(basename "$chart_dir")
    output_file="manifests/${chart_name}.json"
    
    # Skip if manifest already exists and FORCE is not set
    if [[ -f "$output_file" ]] && [[ "${FORCE:-false}" != "true" ]]; then
        echo "      Skipping chart: $chart_name (manifest already exists)"
        continue
    fi

    echo "      Processing chart: $chart_name"
    custom_values_file="${chart_dir}custom-values.yaml"

    # Build the rbac-scope command with or without custom values
    cmd="rbac-scope analyze \"$chart_dir\" -o json"
    if [[ -f "$custom_values_file" ]]; then
        echo "        -> Found custom values file: $custom_values_file"
        cmd+=" -f \"$custom_values_file\""
    fi

    # Execute the command and redirect output to the manifest file
    # Using eval here is safe because we constructed the command ourselves from trusted inputs.
    if eval "$cmd" > "$output_file"; then
        echo "        -> Successfully created manifest: $output_file"
    else
        echo "ERROR: Failed to process chart: $chart_name" >&2
        # Remove potentially incomplete/empty file on failure
        rm -f "$output_file"
    fi
done

echo "SUCCESS: All charts processed."
