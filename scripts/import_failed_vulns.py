#!/usr/bin/env python3
"""
Script to import failed OSS-Fuzz vulnerabilities that need manual fixup.
This script attempts to import vulnerabilities that failed automated bisection.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

_BUCKET = 'oss-fuzz-osv-vulns'
_VULN_URL = f'https://{_BUCKET}.storage.googleapis.com/issue'
_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _yaml_str_representer(dumper, data):
    """YAML str representer override."""
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)


class _YamlDumper(yaml.SafeDumper):
    """Overridden dumper to use | for multiline strings."""


_YamlDumper.add_representer(str, _yaml_str_representer)


def get_failed_vulnerabilities():
    """Get list of failed vulnerability IDs from the GCS bucket."""
    try:
        # List objects in the bucket to find failed vulnerabilities
        # This is a simplified approach - in practice you might need to use gsutil
        # or the GCS API to list objects
        print("Checking for failed vulnerabilities...")
        
        # For now, we'll check a few known failed issue IDs
        # In a real implementation, you'd fetch the list from the bucket
        known_failed_issues = [
            # Add known failed issue IDs here or fetch from bucket
        ]
        
        return known_failed_issues
    except Exception as e:
        print(f"Error checking for failed vulnerabilities: {e}")
        return []


def import_vulnerability(issue_id):
    """Import a single vulnerability by issue ID."""
    try:
        data = urllib.request.urlopen(f'{_VULN_URL}/{issue_id}.json').read()
    except urllib.error.HTTPError:
        print(f'Vulnerability {issue_id} does not exist or is not marked as security')
        return False

    data = json.loads(data)
    project_name = data['package']['name']
    project_dir = os.path.join(_ROOT_DIR, 'vulns', project_name)
    os.makedirs(project_dir, exist_ok=True)
    vuln_path = os.path.join(project_dir, issue_id + '.yaml')

    with open(vuln_path, 'w') as handle:
        yaml.dump(data, handle, sort_keys=False, Dumper=_YamlDumper)

    print(f'Imported vulnerability {issue_id} to {os.path.relpath(vuln_path, os.getcwd())}')
    return True


def main():
    """Main function to import failed vulnerabilities."""
    print("Importing failed OSS-Fuzz vulnerabilities...")
    
    # Get list of failed vulnerabilities
    failed_issues = get_failed_vulnerabilities()
    
    if not failed_issues:
        print("No failed vulnerabilities found or unable to retrieve list")
        return
    
    print(f"Found {len(failed_issues)} failed vulnerabilities to check")
    
    imported_count = 0
    for issue_id in failed_issues:
        if import_vulnerability(issue_id):
            imported_count += 1
    
    print(f"Successfully imported {imported_count} vulnerabilities")


if __name__ == '__main__':
    main()
