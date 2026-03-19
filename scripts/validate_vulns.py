#!/usr/bin/env python3
"""
Script to validate vulnerability files against the OSV schema.
"""

import json
import os
import sys
from pathlib import Path
import yaml
import jsonschema

# OSV schema (simplified version for validation)
OSV_SCHEMA = {
    "type": "object",
    "required": ["id", "summary", "details", "modified", "published", "affected"],
    "properties": {
        "id": {"type": "string"},
        "summary": {"type": "string"},
        "details": {"type": "string"},
        "modified": {"type": "string", "format": "date-time"},
        "published": {"type": "string", "format": "date-time"},
        "withdrawn": {"type": "string", "format": "date-time"},
        "references": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "url"],
                "properties": {
                    "type": {"type": "string"},
                    "url": {"type": "string", "format": "uri"}
                }
            }
        },
        "affected": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["package", "ranges"],
                "properties": {
                    "package": {
                        "type": "object",
                        "required": ["name", "ecosystem"],
                        "properties": {
                            "name": {"type": "string"},
                            "ecosystem": {"type": "string"}
                        }
                    },
                    "ranges": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["type", "events"],
                            "properties": {
                                "type": {"type": "string"},
                                "repo": {"type": "string"},
                                "events": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "introduced": {"type": "string"},
                                            "fixed": {"type": "string"},
                                            "limit": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "versions": {"type": "array", "items": {"type": "string"}},
                    "ecosystem_specific": {"type": "object"},
                    "database_specific": {"type": "object"}
                }
            }
        }
    }
}


def validate_vulnerability_file(file_path):
    """Validate a single vulnerability file."""
    try:
        with open(file_path, 'r') as f:
            vuln_data = yaml.safe_load(f)
        
        # Validate against schema
        jsonschema.validate(vuln_data, OSV_SCHEMA)
        
        # Additional checks
        vuln_id = vuln_data.get('id', '')
        if not vuln_id.startswith('OSV-'):
            print(f"Warning: {file_path} - ID should start with 'OSV-'")
        
        # Check if file name matches ID
        expected_filename = f"{vuln_id}.yaml"
        if file_path.name != expected_filename:
            print(f"Warning: {file_path} - filename should be {expected_filename}")
        
        return True
    except jsonschema.ValidationError as e:
        print(f"Validation error in {file_path}: {e.message}")
        return False
    except Exception as e:
        print(f"Error validating {file_path}: {e}")
        return False


def validate_all_vulnerabilities():
    """Validate all vulnerability files in the repository."""
    vulns_dir = Path(__file__).parent.parent / "vulns"
    
    if not vulns_dir.exists():
        print("No vulnerabilities directory found")
        return True
    
    valid_files = 0
    total_files = 0
    
    for project_dir in vulns_dir.iterdir():
        if project_dir.is_dir():
            for vuln_file in project_dir.glob("*.yaml"):
                total_files += 1
                if validate_vulnerability_file(vuln_file):
                    valid_files += 1
    
    print(f"Validated {valid_files}/{total_files} vulnerability files")
    
    if valid_files != total_files:
        print("Some files failed validation")
        return False
    
    return True


def main():
    """Main validation function."""
    print("Validating vulnerability files...")
    
    if not validate_all_vulnerabilities():
        print("Validation failed")
        sys.exit(1)
    
    print("All vulnerability files are valid")
    sys.exit(0)


if __name__ == "__main__":
    main()
