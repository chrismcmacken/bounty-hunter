#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <organization> [repo1 repo2 ...]"
    echo "Create public test repos on GitHub for CodeQL scanning."
    echo ""
    echo "If no repos specified, lists available repos in the organization directory."
    exit 1
fi

ORG="$1"
shift

if [[ ! -d "$ORG" ]]; then
    echo "Error: Directory '$ORG' not found."
    exit 1
fi

if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is required but not installed."
    exit 1
fi

if ! gh auth status &> /dev/null; then
    echo "Error: Not authenticated with GitHub CLI. Run: gh auth login"
    exit 1
fi

GH_USER=$(gh api user --jq '.login')
PREFIX="${ORG}-test"

# If no repos specified, list available repos
if [[ $# -eq 0 ]]; then
    echo "Available repos in $ORG/:"
    ls -1 "$ORG"
    echo ""
    echo "Usage: $0 $ORG <repo1> <repo2> ..."
    exit 0
fi

echo "Creating test repos under: $GH_USER"
echo "Prefix: $PREFIX-<reponame>"
echo ""

for repo in "$@"; do
    if [[ ! -d "$ORG/$repo" ]]; then
        echo "[$repo] Directory not found, skipping"
        continue
    fi

    test_repo="$PREFIX-$repo"
    echo "[$repo] Creating $GH_USER/$test_repo..."

    # Check if repo already exists
    if gh repo view "$GH_USER/$test_repo" &> /dev/null; then
        echo "[$repo] Repo already exists, skipping creation"
    else
        gh repo create "$test_repo" --public --description "Test mirror of $ORG/$repo for security scanning" || {
            echo "[$repo] Failed to create repo"
            continue
        }
    fi

    # Push code to the new repo
    cd "$ORG/$repo"

    # Add new remote or update existing
    if git remote get-url test-origin &> /dev/null; then
        git remote set-url test-origin "https://github.com/$GH_USER/$test_repo.git"
    else
        git remote add test-origin "https://github.com/$GH_USER/$test_repo.git"
    fi

    echo "[$repo] Pushing to $test_repo..."
    git push test-origin --all --force 2>&1 | sed 's/^/  /'

    cd - > /dev/null

    # Enable CodeQL default setup
    echo "[$repo] Enabling CodeQL..."
    if gh api -X PATCH "repos/$GH_USER/$test_repo/code-scanning/default-setup" \
        -f state=configured \
        -f query_suite=default 2>&1 | sed 's/^/  /'; then
        echo "[$repo] CodeQL enabled"
    else
        echo "[$repo] CodeQL setup failed (may need manual configuration)"
    fi

    echo "[$repo] Done: https://github.com/$GH_USER/$test_repo"
    echo ""
done

echo "Completed. CodeQL scans will run automatically on push."
