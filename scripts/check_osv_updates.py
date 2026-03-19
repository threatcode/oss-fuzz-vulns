#!/usr/bin/env python3
"""
Script to check for new vulnerabilities from OSV and update the local repository.
"""

import json
import os
import sys
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

# OSV API endpoint
OSV_API_URL = "https://api.osv.dev/v1/vulns"
OSS_FUZZ_ECOSYSTEM = "OSS-Fuzz"

def get_existing_vulns():
    """Get list of existing vulnerability IDs in the repository."""
    vulns_dir = Path(__file__).parent.parent / "vulns"
    existing_vulns = set()
    
    if not vulns_dir.exists():
        return existing_vulns
    
    for project_dir in vulns_dir.iterdir():
        if project_dir.is_dir():
            for vuln_file in project_dir.glob("*.yaml"):
                vuln_id = vuln_file.stem
                existing_vulns.add(vuln_id)
    
    return existing_vulns

def fetch_osv_vulns(days_back=7):
    """Fetch recent vulnerabilities from OSV API."""
    # Calculate date range for recent vulnerabilities
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)
    
    # Query parameters
    params = {
        "ecosystem": OSS_FUZZ_ECOSYSTEM,
        "published_after": start_date.isoformat() + "Z",
        "limit": 1000
    }
    
    # Build query URL
    query_string = "&".join([f"{k}={v}" for k, v in params.items()])
    url = f"{OSV_API_URL}?{query_string}"
    
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            return data.get("vulns", [])
    except Exception as e:
        print(f"Error fetching vulnerabilities from OSV: {e}")
        return []

def download_vulnerability(vuln_data, output_path):
    """Download and save a vulnerability file."""
    try:
        # Create directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write vulnerability data as YAML
        import yaml
        
        with open(output_path, 'w') as f:
            yaml.dump(vuln_data, f, sort_keys=False, default_flow_style=False)
        
        print(f"Downloaded: {output_path}")
        return True
    except Exception as e:
        print(f"Error saving vulnerability {vuln_data.get('id', 'unknown')}: {e}")
        return False

def main():
    """Main function to check for updates."""
    print("Checking for OSV vulnerability updates...")
    
    # Get existing vulnerabilities
    existing_vulns = get_existing_vulns()
    print(f"Found {len(existing_vulns)} existing vulnerabilities")
    
    # Fetch recent vulnerabilities from OSV
    osv_vulns = fetch_osv_vulns()
    print(f"Fetched {len(osv_vulns)} recent vulnerabilities from OSV")
    
    # Check for new vulnerabilities
    new_vulns = []
    updates_found = False
    
    for vuln in osv_vulns:
        vuln_id = vuln.get("id")
        if not vuln_id:
            continue
            
        if vuln_id not in existing_vulns:
            new_vulns.append(vuln)
            updates_found = True
    
    # Download new vulnerabilities
    if new_vulns:
        print(f"Found {len(new_vulns)} new vulnerabilities")
        
        for vuln in new_vulns:
            vuln_id = vuln.get("id")
            package_name = vuln.get("affected", [{}])[0].get("package", {}).get("name", "unknown")
            
            # Create output path
            vulns_dir = Path(__file__).parent.parent / "vulns"
            output_path = vulns_dir / package_name / f"{vuln_id}.yaml"
            
            # Download vulnerability
            if download_vulnerability(vuln, output_path):
                print(f"Added: {vuln_id}")
    else:
        print("No new vulnerabilities found")
    
    # Return exit code based on whether updates were found
    # Exit 0 if updates found, 1 if no updates (for GitHub Actions conditional)
    return 0 if updates_found else 1

if __name__ == "__main__":
    sys.exit(main())
