import sys
import re
from pathlib import Path

def bump_version(part):
    pyproject_path = Path("pyproject.toml")
    content = pyproject_path.read_text()
    
    # Regex to find version = "X.Y.Z" inside [project] section (loosely)
    # We assume standard formatting as seen in the file
    match = re.search(r'^version = "(\d+)\.(\d+)\.(\d+)"$', content, re.MULTILINE)
    
    if not match:
        print("Error: Could not find version in pyproject.toml", file=sys.stderr)
        sys.exit(1)
        
    major, minor, patch = map(int, match.groups())
    
    if part == "major":
        major += 1
        minor = 0
        patch = 0
    elif part == "minor":
        minor += 1
        patch = 0
    elif part == "patch":
        patch += 1
    else:
        print(f"Error: Invalid part '{part}'. Use major, minor, or patch.", file=sys.stderr)
        sys.exit(1)
        
    new_version = f"{major}.{minor}.{patch}"
    new_content = content.replace(f'version = "{match.group(1)}.{match.group(2)}.{match.group(3)}"', f'version = "{new_version}"')
    
    pyproject_path.write_text(new_content)
    print(new_version)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python bump_version.py [major|minor|patch]", file=sys.stderr)
        sys.exit(1)
    
    bump_version(sys.argv[1])
