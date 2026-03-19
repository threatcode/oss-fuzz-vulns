#!/usr/bin/env python3
"""
Script to discover new projects by analyzing existing vulnerabilities and finding related projects.
"""

import json
import os
import sys
from datetime import datetime, timedelta, UTC
from pathlib import Path
import yaml

# OSV ecosystem
OSS_FUZZ_ECOSYSTEM = "OSS-Fuzz"

def get_existing_projects():
    """Get list of existing project names in repository."""
    vulns_dir = Path(__file__).parent.parent / "vulns"
    projects = set()
    
    if not vulns_dir.exists():
        return projects
    
    for project_dir in vulns_dir.iterdir():
        if project_dir.is_dir():
            projects.add(project_dir.name)
    
    return projects

def extract_projects_from_vulnerabilities():
    """Extract project names from existing vulnerabilities to find related projects."""
    vulns_dir = Path(__file__).parent.parent / "vulns"
    related_projects = set()
    
    if not vulns_dir.exists():
        return related_projects
    
    # Read existing vulnerabilities to extract repository information
    for project_dir in vulns_dir.iterdir():
        if not project_dir.is_dir():
            continue
            
        for vuln_file in project_dir.glob("*.yaml"):
            try:
                with open(vuln_file, 'r') as f:
                    vuln_data = yaml.safe_load(f)
                
                # Extract repository URLs to find related projects
                affected = vuln_data.get("affected", [])
                for aff in affected:
                    ranges = aff.get("ranges", [])
                    for range_info in ranges:
                        if range_info.get("type") == "GIT":
                            repo_url = range_info.get("repo", "")
                            if repo_url:
                                # Extract project name from GitHub URL
                                if "github.com" in repo_url:
                                    project_name = repo_url.split("/")[-1].replace(".git", "")
                                    if project_name != project_dir.name:  # Different from current project
                                        related_projects.add(project_name)
                
                # Extract from references
                references = vuln_data.get("references", [])
                for ref in references:
                    if isinstance(ref, dict):
                        url = ref.get("url", "")
                        if "github.com" in url and "/issues/" not in url:
                            # Extract potential project name
                            parts = url.split("/")
                            if len(parts) >= 2:
                                project_name = parts[-1].replace(".git", "")
                                related_projects.add(project_name)
                
            except Exception as e:
                continue
    
    return related_projects

def discover_new_projects():
    """Discover new projects from multiple sources."""
    existing_projects = get_existing_projects()
    related_projects = extract_projects_from_vulnerabilities()
    
    new_projects = []
    
    try:
        import requests
        OSV_QUERY_URL = "https://api.osv.dev/v1/query"
        
        for project in related_projects:
            if project in existing_projects:
                continue
                
            query_payload = {
                "package": {
                    "name": project,
                    "ecosystem": OSS_FUZZ_ECOSYSTEM
                }
            }
            
            try:
                response = requests.post(OSV_QUERY_URL, json=query_payload, timeout=10)
                response.raise_for_status()
                
                result = response.json()
                vulns = result.get("vulns", [])
                
                if vulns:
                    new_projects.append({
                        "name": project,
                        "vulnerabilities": len(vulns),
                        "latest_vuln": vulns[0].get("published", ""),
                        "source": "related"
                    })
                    print(f"Found related project: {project} ({len(vulns)} vulnerabilities)")
                
            except Exception as e:
                # Silently continue if project doesn't exist or API fails
                continue
        
        return new_projects
        
    except Exception as e:
        print(f"Error discovering new projects: {e}")
        return []

def create_project_directory(project_name):
    """Create directory structure for a new project."""
    vulns_dir = Path(__file__).parent.parent / "vulns"
    project_dir = vulns_dir / project_name
    
    try:
        project_dir.mkdir(parents=True, exist_ok=True)
        
        # Create README for the project
        readme_content = f"""# {project_name}

Vulnerabilities for {project_name} in the OSS-Fuzz ecosystem.

## Statistics

Total vulnerabilities: 0

## Latest Updates

This directory is automatically updated by the daily update workflow.

"""
        
        readme_path = project_dir / "README.md"
        with open(readme_path, 'w') as f:
            f.write(readme_content)
        
        print(f"Created project directory: {project_dir}")
        return True
        
    except Exception as e:
        print(f"Error creating project directory for {project_name}: {e}")
        return False

def main():
    """Main function to discover and add new projects."""
    print("Discovering new OSS-Fuzz projects from existing vulnerabilities...")
    
    existing_projects = get_existing_projects()
    print(f"Currently tracking {len(existing_projects)} projects")
    
    related_projects = extract_projects_from_vulnerabilities()
    print(f"Found {len(related_projects)} potentially related projects")
    
    new_projects = discover_new_projects()
    
    if not new_projects:
        print("No new projects found")
        return 1
    
    print(f"\nFound {len(new_projects)} new projects:")
    for project in new_projects:
        print(f"  - {project['name']}: {project['vulnerabilities']} vulnerabilities (source: {project['source']})")
    
    # Create directories for new projects
    created_count = 0
    for project in new_projects:
        if create_project_directory(project['name']):
            created_count += 1
    
    print(f"\nCreated {created_count} new project directories")
    return 0 if created_count > 0 else 1

if __name__ == "__main__":
    sys.exit(main())
