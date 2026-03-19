#!/usr/bin/env python3
"""
Script to automatically discover and add new projects from OSV that don't exist locally.
"""

import json
import os
import sys
from datetime import datetime, timedelta, UTC
from pathlib import Path

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

def discover_new_projects():
    """Discover new projects from OSV that don't exist locally."""
    # Since we can't query by ecosystem alone, we'll use a different approach
    # We'll search for common OSS-Fuzz projects and check if they exist
    
    # List of common OSS-Fuzz projects to check
    known_projects = [
        "openssl", "libxml2", "sqlite", "curl", "nginx", "apache", "php",
        "python", "ruby", "golang", "rust", "ffmpeg", "imagemagick",
        "libpng", "libjpeg", "libtiff", "zlib", "bzip2", "xz",
        "redis", "postgresql", "mysql", "mongodb", "nginx", "haproxy",
        "wireshark", "tcpdump", "nmap", "metasploit", "burp",
        "chromium", "firefox", "safari", "edge", "opera",
        "linux", "windows", "macos", "android", "ios",
        "gcc", "clang", "llvm", "rustc", "javac",
        "docker", "kubernetes", "terraform", "ansible", "puppet",
        "aws", "azure", "gcp", "terraform", "cloudflare",
        "tensorflow", "pytorch", "keras", "scikit-learn", "pandas",
        "react", "vue", "angular", "svelte", "nextjs",
        "nodejs", "deno", "bun", "express", "koa",
        "django", "flask", "rails", "spring", "laravel",
        "mongodb", "cassandra", "couchdb", "elasticsearch", "solr",
        "rabbitmq", "kafka", "zookeeper", "consul", "etcd",
        "jenkins", "gitlab", "github", "bitbucket", "circleci"
    ]
    
    existing_projects = get_existing_projects()
    new_projects = []
    
    try:
        import requests
        OSV_QUERY_URL = "https://api.osv.dev/v1/query"
        
        for project in known_projects:
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
                        "latest_vuln": vulns[0].get("published", "")
                    })
                    print(f"Found new project: {project} ({len(vulns)} vulnerabilities)")
                
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
    print("Discovering new OSS-Fuzz projects...")
    
    existing_projects = get_existing_projects()
    print(f"Currently tracking {len(existing_projects)} projects")
    
    new_projects = discover_new_projects()
    
    if not new_projects:
        print("No new projects found")
        return 1
    
    print(f"\nFound {len(new_projects)} new projects:")
    for project in new_projects:
        print(f"  - {project['name']}: {project['vulnerabilities']} vulnerabilities")
    
    # Create directories for new projects
    created_count = 0
    for project in new_projects:
        if create_project_directory(project['name']):
            created_count += 1
    
    print(f"\nCreated {created_count} new project directories")
    return 0 if created_count > 0 else 1

if __name__ == "__main__":
    sys.exit(main())
