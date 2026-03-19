#!/usr/bin/env python3
"""
Script to check for potentially outdated vulnerability information.
"""

import os
import sys
from pathlib import Path
import yaml
from datetime import datetime, timedelta

def get_vulnerability_data(file_path):
    """Extract vulnerability data from YAML file."""
    try:
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
        return data
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def check_outdated_vulnerabilities():
    """Check for potentially outdated vulnerability information."""
    vulns_dir = Path(__file__).parent.parent / "vulns"
    
    if not vulns_dir.exists():
        print("No vulnerabilities directory found")
        return
    
    now = datetime.utcnow()
    six_months_ago = now - timedelta(days=180)
    one_year_ago = now - timedelta(days=365)
    
    outdated_issues = []
    very_old_issues = []
    missing_version_info = []
    potential_fixes = []
    
    total_files = 0
    
    for project_dir in vulns_dir.iterdir():
        if project_dir.is_dir():
            for vuln_file in project_dir.glob("*.yaml"):
                total_files += 1
                data = get_vulnerability_data(vuln_file)
                
                if not data:
                    continue
                
                vuln_id = data.get('id', '')
                modified = data.get('modified', '')
                published = data.get('published', '')
                
                # Check modification date
                if modified:
                    try:
                        modified_date = datetime.fromisoformat(modified.replace('Z', '+00:00'))
                        if modified_date < one_year_ago:
                            very_old_issues.append((vuln_id, modified_date, vuln_file))
                        elif modified_date < six_months_ago:
                            outdated_issues.append((vuln_id, modified_date, vuln_file))
                    except:
                        pass
                
                # Check for missing version information
                affected = data.get('affected', [])
                has_versions = False
                for aff in affected:
                    if aff.get('versions'):
                        has_versions = True
                        break
                
                if not has_versions:
                    missing_version_info.append((vuln_id, vuln_file))
                
                # Check for potential fixes (vulnerabilities without fixed commits)
                for aff in affected:
                    ranges = aff.get('ranges', [])
                    for range_info in ranges:
                        events = range_info.get('events', [])
                        has_fixed = any('fixed' in event for event in events)
                        if not has_fixed and range_info.get('type') == 'GIT':
                            potential_fixes.append((vuln_id, vuln_file))
    
    print(f"Checked {total_files} vulnerability files")
    
    # Report findings
    print(f"\n=== Vulnerabilities Not Updated in >6 Months ({len(outdated_issues)}) ===")
    for vuln_id, modified_date, file_path in sorted(outdated_issues, key=lambda x: x[1]):
        days_old = (datetime.utcnow() - modified_date.replace(tzinfo=None)).days
        print(f"{vuln_id}: {days_old} days old ({file_path})")
    
    print(f"\n=== Vulnerabilities Not Updated in >1 Year ({len(very_old_issues)}) ===")
    for vuln_id, modified_date, file_path in sorted(very_old_issues, key=lambda x: x[1]):
        days_old = (datetime.utcnow() - modified_date.replace(tzinfo=None)).days
        print(f"{vuln_id}: {days_old} days old ({file_path})")
    
    print(f"\n=== Missing Version Information ({len(missing_version_info)}) ===")
    for vuln_id, file_path in missing_version_info[:20]:  # Limit output
        print(f"{vuln_id}: {file_path}")
    
    if len(missing_version_info) > 20:
        print(f"... and {len(missing_version_info) - 20} more")
    
    print(f"\n=== Potential Missing Fixes ({len(potential_fixes)}) ===")
    for vuln_id, file_path in potential_fixes[:20]:  # Limit output
        print(f"{vuln_id}: {file_path}")
    
    if len(potential_fixes) > 20:
        print(f"... and {len(potential_fixes) - 20} more")
    
    # Summary
    total_issues = len(outdated_issues) + len(very_old_issues) + len(missing_version_info) + len(potential_fixes)
    print(f"\n=== Summary ===")
    print(f"Total issues found: {total_issues}")
    print(f"- Not updated in 6+ months: {len(outdated_issues)}")
    print(f"- Not updated in 1+ year: {len(very_old_issues)}")
    print(f"- Missing version info: {len(missing_version_info)}")
    print(f"- Potential missing fixes: {len(potential_fixes)}")
    
    return total_issues

def main():
    """Main function to check for outdated vulnerabilities."""
    print("Checking for outdated vulnerability information...")
    
    total_issues = check_outdated_vulnerabilities()
    
    if total_issues > 0:
        print(f"\nFound {total_issues} issues that may need attention")
        sys.exit(1)
    else:
        print("\nNo issues found")
        sys.exit(0)

if __name__ == "__main__":
    main()
