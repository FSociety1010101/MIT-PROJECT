# Publish helper for EthSAST
# Run this from the project root once Git is installed.

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Error "Git is not installed or not available in PATH. Install Git first."
    exit 1
}

if (Test-Path .git) {
    Write-Host "Repository already initialized."
    exit 0
}

git init
git add .
git commit -m "chore: initial publish-ready EthSAST commit"
git tag v1.0.0

Write-Host "Git repository initialized, committed, and tagged v1.0.0."
