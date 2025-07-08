#!/usr/bin/env python3

import json
import csv
import os
from pathlib import Path
from typing import Dict, Any

def count_arrays_recursive(data: Dict[str, Any]) -> Dict[str, int]:
    """Recursively search for specific arrays and count their elements."""
    array_counts = {
        'serviceAccountData_count': 0,
        'serviceAccountPermissions_count': 0,
        'serviceAccountWorkloads_count': 0,
        'risk_critical_count': 0,
        'risk_high_count': 0,
        'risk_medium_count': 0,
        'risk_low_count': 0,
    }

    def _search(obj: Any):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, list):
                    if k == 'serviceAccountPermissions':
                        array_counts[f'{k}_count'] = len(v)
                        # Count risk levels in permissions
                        for perm in v:
                            if isinstance(perm, dict) and 'riskLevel' in perm:
                                risk_level = f"risk_{perm['riskLevel'].lower()}_count"
                                if risk_level in array_counts:
                                    array_counts[risk_level] += 1
                    elif k in ['serviceAccountData', 'serviceAccountWorkloads']:
                        array_counts[f'{k}_count'] = len(v)
                _search(v)
        elif isinstance(obj, list):
            for item in obj:
                _search(item)

    _search(data)
    return array_counts

def flatten_json(data: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    """Flatten nested JSON structure into a flat dictionary with compound keys."""
    items: list = []

    # First get all array counts
    array_counts = count_arrays_recursive(data)

    # Then flatten the structure
    for k, v in data.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k

        if isinstance(v, dict):
            items.extend(flatten_json(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # Convert lists to string representation
            items.append((new_key, str(v)))
        else:
            items.append((new_key, v))

    # Add array count fields
    items.extend(array_counts.items())
    return dict(items)

def process_json_files(manifests_dir: str) -> list:
    """Process all JSON files in the manifests directory and return flattened data."""
    all_data = []
    manifests_path = Path(manifests_dir)

    for json_file in manifests_path.glob('*.json'):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                # Add filename as a field
                flattened = flatten_json(data)
                flattened['source_file'] = json_file.name
                all_data.append(flattened)
        except Exception as e:
            print(f"Error processing {json_file}: {e}")

    return all_data

def write_csv_report(data: list, output_file: str):
    """Write the flattened data to a CSV file."""
    if not data:
        print("No data to write!")
        return

    # Get all possible keys from all records
    fieldnames = set()
    for record in data:
        fieldnames.update(record.keys())

    # Sort fieldnames for consistency
    fieldnames = sorted(list(fieldnames))

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def main():
    manifests_dir = "manifests"
    output_file = "rbac_report.csv"

    print(f"Processing JSON files from {manifests_dir}...")
    data = process_json_files(manifests_dir)
    print(f"Found {len(data)} JSON files")

    print(f"Writing report to {output_file}...")
    write_csv_report(data, output_file)
    print("Done!")

if __name__ == "__main__":
    main()
