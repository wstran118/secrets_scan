import os
import re
import sys
import json
import requests
from pathlib import Path
import fnmatch
from datetime import datetime

def send_to_siem(event_data, siem_url, siem_token):
    """Send event data to SIEM (e.g., Splunk HTTP Event Collector)."""
    headers = {
        'Authorization': f'Splunk {siem_token}',
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(siem_url, headers=headers, json=event_data, timeout=10)
        if response.status_code != 200:
            print(f"Failed to send event to SIEM: {response.text}")
        else:
            print("Event successfully sent to SIEM")
    except requests.RequestException as e:
        print(f"Error sending to SIEM: {e}")

def check_secrets(directory, siem_url=None, siem_token=None):
    # Common patterns for secrets and API keys
    secret_patterns = [
        (r'AKIA[0-9A-Z]{16}', 'HIGH'),  # AWS Access Key (high severity)
        (r'[0-9a-f]{32}', 'MEDIUM'),    # Generic 32-char hex key (e.g., API keys)
        (r'sk_[0-9a-f]{20,}', 'HIGH'),  # Stripe secret key (high severity)
        (r'[A-Za-z0-9_-]{20,}', 'MEDIUM'),  # Generic long alphanumeric key
        (r'(?i)secret\s*=\s*["\'][^"\']+["\']', 'HIGH'),  # Generic secret assignment
        (r'(?i)api_key\s*=\s*["\'][^"\']+["\']', 'HIGH'),  # API key assignment
        (r'(?i)password\s*=\s*["\'][^"\']+["\']', 'HIGH')  # Password assignment
    ]

    # Common environment variable patterns
    env_var_patterns = [
        r'os\.environ\.get\(["\'](.*?)["\']\)',  # os.environ.get('VAR')
        r'os\.getenv\(["\'](.*?)["\']\)'        # os.getenv('VAR')
    ]

    # File extensions to scan
    include_extensions = ['*.py', '*.js', '*.ts', '*.java', '*.rb', '*.go', '*.php']
    # Files/folders to ignore
    ignore_patterns = ['node_modules', 'venv', '.git', '__pycache__', '*.log']

    exposed_secrets = []
    used_env_vars = set()

    def should_ignore(path):
        return any(fnmatch.fnmatch(path, pattern) or pattern in path for pattern in ignore_patterns)

    def scan_file(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                lines = content.splitlines()

                # Check for hardcoded secrets
                for pattern, severity in secret_patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        exposed_secrets.append({
                            'file': str(file_path),
                            'line': line_num,
                            'secret': match.group(),
                            'severity': severity
                        })

                # Check for environment variable usage
                for pattern in env_var_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        used_env_vars.add(match.group(1))

        except (UnicodeDecodeError, IOError):
            print(f"Warning: Could not read file {file_path}")

    # Walk through directory
    for root, _, files in os.walk(directory):
        if should_ignore(root):
            continue

        for file in files:
            if any(fnmatch.fnmatch(file, ext) for ext in include_extensions):
                file_path = Path(root) / file
                if not should_ignore(str(file_path)):
                    scan_file(file_path)

    # Check if used environment variables are actually set
    missing_env_vars = []
    for env_var in used_env_vars:
        if env_var not in os.environ:
            missing_env_vars.append(env_var)

    # Prepare JSON report
    result = {
        'secrets': exposed_secrets,
        'missing_env_vars': missing_env_vars,
        'scan_directory': directory,
        'timestamp': datetime.utcnow().isoformat()
    }

    # Save JSON report
    report_path = 'secret_scan_report.json'
    with open(report_path, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"Scan report saved to {report_path}")

    # Send events to SIEM if configured
    if siem_url and siem_token:
        for secret in exposed_secrets:
            event = {
                'event': 'secret_detected',
                'details': secret,
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'secret_scanner',
                'directory': directory
            }
            send_to_siem(event, siem_url, siem_token)

        for env_var in missing_env_vars:
            event = {
                'event': 'missing_env_var',
                'details': {'variable': env_var},
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'secret_scanner',
                'directory': directory
            }
            send_to_siem(event, siem_url, siem_token)

    # Print human-readable output
    if exposed_secrets:
        print("\nPotentially Hardcoded Secrets Found:")
        for secret in exposed_secrets:
            print(f"File: {secret['file']}, Line: {secret['line']}, Secret: {secret['secret']}, Severity: {secret['severity']}")
    else:
        print("\nNo hardcoded secrets detected.")

    if missing_env_vars:
        print("\nMissing Environment Variables:")
        for var in missing_env_vars:
            print(f"Environment variable '{var}' is referenced but not set.")
    else:
        print("\nAll referenced environment variables are set.")

    # Return non-zero exit code if issues are found for CI/CD failure
    if exposed_secrets or missing_env_vars:
        sys.exit(1)
    return exposed_secrets, missing_env_vars

if __name__ == "__main__":
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    siem_url = os.environ.get('SIEM_URL')  # e.g., https://splunk-hec.example.com/services/collector
    siem_token = os.environ.get('SIEM_TOKEN')  # Splunk HEC token
    print(f"Scanning directory: {directory}")
    check_secrets(directory, siem_url, siem_token)