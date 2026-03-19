#!/usr/bin/env python3
"""
Script to check for duplicate vulnerabilities in the repository.
"""

import os
import sys
from pathlib import Path
import yaml
from collections import defaultdict

def get_vulnerability_data(file_path):
    """Extract vulnerability data from YAML file."""
    try:
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
        return data
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def find_duplicates():
    """Find duplicate vulnerabilities based on various criteria."""
    vulns_dir = Path(__file__).parent.parent / "vulns"
    
    if not vulns_dir.exists():
        print("No vulnerabilities directory found")
        return
    
    # Track vulnerabilities by different criteria
    by_id = {}
    by_summary = defaultdict(list)
    by_reference = defaultdict(list)
    
    total_files = 0
    
    for project_dir in vulns_dir.iterdir():
        if project_dir.is_dir():
            for vuln_file in project_dir.glob("*.yaml"):
                total_files += 1
                data = get_vulnerability_data(vuln_file)
                
                if not data:
                    continue
                
                vuln_id = data.get('id', '')
                summary = data.get('summary', '')
                references = data.get('references', [])
                
                # Check for duplicate IDs
                if vuln_id in by_id:
                    print(f"DUPLICATE ID FOUND: {vuln_id}")
                    print(f"  Existing: {by_id[vuln_id]}")
                    print(f"  New: {vuln_file}")
                else:
                    by_id[vuln_id] = vuln_file
                
                # Check for duplicate summaries (potential duplicates)
                by_summary[summary].append((vuln_file, vuln_id))
                
                # Check for duplicate references
                for ref in references:
                    if isinstance(ref, dict) and 'url' in ref:
                        url = ref['url']
                        by_reference[url].append((vuln_file, vuln_id))
    
    print(f"Checked {total_files} vulnerability files")
    
    # Report potential duplicates
    duplicates_found = False
    
    print("\n=== Potential Duplicate Summaries ===")
    for summary, files in by_summary.items():
        if len(files) > 1 and summary:  # Skip empty summaries
            duplicates_found = True
            print(f"Summary: {summary}")
            for file_path, vuln_id in files:
                print(f"  - {vuln_id}: {file_path}")
    
    print("\n=== Duplicate References ===")
    for url, files in by_reference.items():
        if len(files) > 1:
            duplicates_found = True
            print(f"Reference: {url}")
            for file_path, vuln_id in files:
                print(f"  - {vuln_id}: {file_path}")
    
    if not duplicates_found:
        print("No duplicates found")
    
    return duplicates_found

def main():
    """Main function to check for duplicates."""
    print("Checking for duplicate vulnerabilities...")
    
    duplicates_found = find_duplicates()
    
    if duplicates_found:
        print("Duplicates found - please review and resolve")
        sys.exit(1)
    else:
        print("No duplicates detected")
        sys.exit(0)

if __name__ == "__main__":
    main()
