import os
import re
from pathlib import Path
import fnmatch

def check_secrets(directory):
    # Common patterns for secrets and API keys
    secret_patterns = [
        r'AKIA[0-9A-Z]{16}',  # AWS Access Key
        r'[0-9a-f]{32}',      # Generic 32-char hex key (e.g., API keys)
        r'sk_[0-9a-f]{20,}',  # Stripe secret key
        r'[A-Za-z0-9_-]{20,}', # Generic long alphanumeric key
        r'(?i)secret\s*=\s*["\'][^"\']+["\']',  # Generic secret assignment
        r'(?i)api_key\s*=\s*["\'][^"\']+["\']', # API key assignment
        r'(?i)password\s*=\s*["\'][^"\']+["\']' # Password assignment
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
                for pattern in secret_patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        exposed_secrets.append({
                            'file': str(file_path),
                            'line': line_num,
                            'secret': match.group()
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

    # Print results
    if exposed_secrets:
        print("\nPotentially Hardcoded Secrets Found:")
        for secret in exposed_secrets:
            print(f"File: {secret['file']}, Line: {secret['line']}, Secret: {secret['secret']}")
    else:
        print("\nNo hardcoded secrets detected.")

    if missing_env_vars:
        print("\nMissing Environment Variables:")
        for var in missing_env_vars:
            print(f"Environment variable '{var}' is referenced but not set.")
    else:
        print("\nAll referenced environment variables are set.")

    return exposed_secrets, missing_env_vars

if __name__ == "__main__":
    import sys
    directory = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning directory: {directory}")
    check_secrets(directory)