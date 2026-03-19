#!/usr/bin/env python3
"""
Script to generate repository statistics.
"""

import os
import sys
from pathlib import Path
import yaml
from datetime import datetime
from collections import defaultdict, Counter

def get_vulnerability_data(file_path):
    """Extract vulnerability data from YAML file."""
    try:
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
        return data
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def generate_statistics():
    """Generate comprehensive repository statistics."""
    vulns_dir = Path(__file__).parent.parent / "vulns"
    
    if not vulns_dir.exists():
        print("# Repository Statistics\n\nNo vulnerabilities directory found.")
        return
    
    stats = {
        'total_vulnerabilities': 0,
        'projects': defaultdict(int),
        'severities': Counter(),
        'years': Counter(),
        'withdrawn': 0,
        'with_references': 0,
        'with_versions': 0,
        'crash_types': Counter()
    }
    
    # Process all vulnerability files
    for project_dir in vulns_dir.iterdir():
        if project_dir.is_dir():
            project_name = project_dir.name
            
            for vuln_file in project_dir.glob("*.yaml"):
                data = get_vulnerability_data(vuln_file)
                
                if not data:
                    continue
                
                stats['total_vulnerabilities'] += 1
                stats['projects'][project_name] += 1
                
                # Extract year from published date
                published = data.get('published', '')
                if published:
                    try:
                        year = datetime.fromisoformat(published.replace('Z', '+00:00')).year
                        stats['years'][year] += 1
                    except:
                        pass
                
                # Check if withdrawn
                if data.get('withdrawn'):
                    stats['withdrawn'] += 1
                
                # Check for references
                if data.get('references'):
                    stats['with_references'] += 1
                
                # Check for versions
                affected = data.get('affected', [])
                for aff in affected:
                    if aff.get('versions'):
                        stats['with_versions'] += 1
                        break
                
                # Extract severity
                for aff in affected:
                    eco_specific = aff.get('ecosystem_specific', {})
                    severity = eco_specific.get('severity')
                    if severity:
                        stats['severities'][severity] += 1
                
                # Extract crash types from details
                details = data.get('details', '')
                if 'Crash type:' in details:
                    try:
                        crash_type = details.split('Crash type:')[1].split('\n')[0].strip()
                        stats['crash_types'][crash_type] += 1
                    except:
                        pass
    
    # Generate markdown report
    report = []
    report.append("# Repository Statistics")
    report.append("")
    report.append(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    report.append("")
    
    # Summary
    report.append("## Summary")
    report.append("")
    report.append(f"- **Total Vulnerabilities**: {stats['total_vulnerabilities']:,}")
    report.append(f"- **Unique Projects**: {len(stats['projects'])}")
    report.append(f"- **Withdrawn**: {stats['withdrawn']}")
    report.append(f"- **With References**: {stats['with_references']}")
    report.append(f"- **With Version Info**: {stats['with_versions']}")
    report.append("")
    
    # Top projects
    report.append("## Top 10 Projects by Vulnerability Count")
    report.append("")
    report.append("| Project | Count |")
    report.append("|---------|-------|")
    
    for project, count in sorted(stats['projects'].items(), key=lambda x: x[1], reverse=True)[:10]:
        report.append(f"| {project} | {count} |")
    
    report.append("")
    
    # Severity distribution
    if stats['severities']:
        report.append("## Severity Distribution")
        report.append("")
        for severity, count in stats['severities'].most_common():
            report.append(f"- **{severity}**: {count}")
        report.append("")
    
    # Year distribution
    if stats['years']:
        report.append("## Vulnerabilities by Year")
        report.append("")
        report.append("| Year | Count |")
        report.append("|------|-------|")
        
        for year in sorted(stats['years'].keys()):
            count = stats['years'][year]
            report.append(f"| {year} | {count} |")
        
        report.append("")
    
    # Top crash types
    if stats['crash_types']:
        report.append("## Top 10 Crash Types")
        report.append("")
        report.append("| Crash Type | Count |")
        report.append("|------------|-------|")
        
        for crash_type, count in stats['crash_types'].most_common(10):
            report.append(f"| {crash_type} | {count} |")
        
        report.append("")
    
    # All projects (if not too many)
    if len(stats['projects']) <= 50:
        report.append("## All Projects")
        report.append("")
        for project, count in sorted(stats['projects'].items()):
            report.append(f"- **{project}**: {count}")
        report.append("")
    else:
        report.append(f"## All Projects")
        report.append("")
        report.append(f"*Showing top 50 of {len(stats['projects'])} projects*")
        report.append("")
        for project, count in sorted(stats['projects'].items(), key=lambda x: x[1], reverse=True)[:50]:
            report.append(f"- **{project}**: {count}")
        report.append("")
    
    print("\n".join(report))

def main():
    """Main function to generate statistics."""
    generate_statistics()

if __name__ == "__main__":
    main()
