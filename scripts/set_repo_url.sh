#!/usr/bin/env bash
# Usage: ./scripts/set_repo_url.sh <REAL_GITHUB_REPO_URL>
# Example: ./scripts/set_repo_url.sh https://github.com/my-org/my-private-repo

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <REAL_GITHUB_REPO_URL>"
    echo "Example: $0 https://github.com/my-org/my-private-repo"
    exit 1
fi

TARGET_URL="$1"
# Strip trailing .git if provided
TARGET_URL="${TARGET_URL%.git}"

echo "Substituting <REPO_URL> with '${TARGET_URL}'..."

FILES=(
    "Cargo.toml"
    ".github/ISSUE_TEMPLATE/config.yml"
    "README.md"
    "README.en.md"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        sed -i "s|<REPO_URL>|${TARGET_URL}|g" "$file"
        echo "  [OK] Updated $file"
    else
        echo "  [WARN] File not found: $file"
    fi
done

echo "Done! All repository placeholders updated."
