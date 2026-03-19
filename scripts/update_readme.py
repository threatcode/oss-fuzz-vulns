#!/usr/bin/env python3
"""
Script to update README.md with latest statistics.
"""

import os
import sys
from pathlib import Path
import yaml
from datetime import datetime
from collections import defaultdict

def count_vulnerabilities():
    """Count total vulnerabilities and projects."""
    vulns_dir = Path(__file__).parent.parent / "vulns"
    
    if not vulns_dir.exists():
        return 0, 0
    
    total_vulns = 0
    projects = set()
    
    for project_dir in vulns_dir.iterdir():
        if project_dir.is_dir():
            projects.add(project_dir.name)
            for vuln_file in project_dir.glob("*.yaml"):
                total_vulns += 1
    
    return total_vulns, len(projects)

def update_readme():
    """Update README.md with current statistics."""
    readme_path = Path(__file__).parent.parent / "README.md"
    
    if not readme_path.exists():
        print("README.md not found")
        return False
    
    # Read current README
    with open(readme_path, 'r') as f:
        content = f.read()
    
    # Get current statistics
    total_vulns, total_projects = count_vulnerabilities()
    current_date = datetime.now().strftime('%Y-%m-%d')
    
    # Find and update the statistics section
    lines = content.split('\n')
    new_lines = []
    stats_updated = False
    
    for i, line in enumerate(lines):
        # Look for existing statistics section
        if '## Statistics' in line or '## Repository Statistics' in line:
            # Replace the entire statistics section
            new_lines.append(line)
            new_lines.append('')
            new_lines.append(f"- **Total Vulnerabilities**: {total_vulns:,}")
            new_lines.append(f"- **Projects**: {total_projects}")
            new_lines.append(f"- **Last Updated**: {current_date}")
            new_lines.append('')
            stats_updated = True
            
            # Skip old stats lines
            i += 1
            while i < len(lines) and not lines[i].startswith('##'):
                i += 1
            i -= 1  # Back up one since the loop will increment
        else:
            new_lines.append(line)
    
    # If no statistics section found, add one before the Automation section
    if not stats_updated:
        updated_lines = []
        for i, line in enumerate(new_lines):
            updated_lines.append(line)
            if '## Automation' in line:
                # Insert statistics before automation
                updated_lines.append('')
                updated_lines.append('## Statistics')
                updated_lines.append('')
                updated_lines.append(f"- **Total Vulnerabilities**: {total_vulns:,}")
                updated_lines.append(f"- **Projects**: {total_projects}")
                updated_lines.append(f"- **Last Updated**: {current_date}")
                updated_lines.append('')
                updated_lines.append('')
        new_lines = updated_lines
    
    # Write updated README
    with open(readme_path, 'w') as f:
        f.write('\n'.join(new_lines))
    
    print(f"Updated README.md with {total_vulns:,} vulnerabilities across {total_projects} projects")
    return True

def main():
    """Main function to update README."""
    print("Updating README.md with latest statistics...")
    
    if update_readme():
        print("README.md updated successfully")
    else:
        print("Failed to update README.md")
        sys.exit(1)

if __name__ == "__main__":
    main()
