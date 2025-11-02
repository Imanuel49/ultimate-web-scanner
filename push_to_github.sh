#!/bin/bash

# 🚀 Ultimate Web Scanner - GitHub Upload Script
# Repository: https://github.com/Imanuel49/ultimate-web-scanner

echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                           ║"
echo "║      ULTIMATE WEB SCANNER v5.2 - GITHUB UPLOAD                          ║"
echo "║      Pushing to: Imanuel49/ultimate-web-scanner                         ║"
echo "║                                                                           ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""

# Set repository URL
REPO_URL="https://github.com/Imanuel49/ultimate-web-scanner.git"

echo "[1/5] Checking Git status..."
git status

echo ""
echo "[2/5] Adding remote origin..."
git remote remove origin 2>/dev/null || true
git remote add origin $REPO_URL

echo ""
echo "[3/5] Verifying remote..."
git remote -v

echo ""
echo "[4/5] Ready to push!"
echo ""
echo "Repository: $REPO_URL"
echo "Branch: main"
echo "Files: $(git ls-files | wc -l) files"
echo ""

# Show what will be pushed
echo "Files to be pushed:"
git ls-tree -r main --name-only | head -20
echo "... and $(git ls-files | wc -l) total files"

echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                           ║"
echo "║      READY TO PUSH!                                                      ║"
echo "║                                                                           ║"
echo "║      To complete the upload, run:                                        ║"
echo "║      $ git push -u origin main                                           ║"
echo "║                                                                           ║"
echo "║      Note: You'll need GitHub credentials or Personal Access Token       ║"
echo "║                                                                           ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""

# Optional: Uncomment to push automatically
# echo "[5/5] Pushing to GitHub..."
# git push -u origin main

echo "✅ Setup complete! Ready to push to GitHub."
echo ""
echo "Manual push command:"
echo "  git push -u origin main"
echo ""
