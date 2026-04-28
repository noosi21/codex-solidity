#!/bin/bash
# ═══════════════════════════════════════════════════════
# Codex Solidity — Interactive Quick Start
# Just run: npm run quickstart
# ═════════════════════════════════════════════════════════

set -e

BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo ""
echo -e "${RED}═══════════════════════════════════════════${NC}"
echo -e "${RED}  ⛓️  Codex Solidity — Quick Start${NC}"
echo -e "${RED}═══════════════════════════════════════════${NC}"
echo ""

# Check if installed
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Dependencies not installed. Running npm install...${NC}"
    npm install --silent
    echo ""
fi

# Ask what to audit
echo -e "${CYAN}What do you want to audit?${NC}"
echo ""
echo "  1) GitHub repo URL (e.g., https://github.com/OpenZeppelin/openzeppelin-contracts)"
echo "  2) Local directory (e.g., ./contracts/)"
echo "  3) Single .sol file (e.g., ./Vault.sol)"
echo "  4) List available skills"
echo "  5) Start Codex CLI interactive session"
echo ""
echo -ne "${BOLD}Enter choice (1-5): ${NC}"
read -r CHOICE

case $CHOICE in
    1)
        echo -ne "${BOLD}Enter GitHub URL: ${NC}"
        read -r TARGET
        if [ -z "$TARGET" ]; then
            echo -e "${RED}No URL provided. Exiting.${NC}"
            exit 1
        fi
        echo ""
        echo -e "${GREEN}Running aggressive audit on $TARGET...${NC}"
        echo ""
        node bin/codex-sol.js audit -t "$TARGET" --aggressive --authorize --llm --reasoning-effort xhigh
        ;;
    2)
        echo -ne "${BOLD}Enter directory path: ${NC}"
        read -r TARGET
        if [ -z "$TARGET" ]; then TARGET="./contracts/"; fi
        echo ""
        echo -e "${GREEN}Running aggressive audit on $TARGET...${NC}"
        echo ""
        node bin/codex-sol.js audit -t "$TARGET" --aggressive --authorize --llm --reasoning-effort xhigh
        ;;
    3)
        echo -ne "${BOLD}Enter .sol file path: ${NC}"
        read -r TARGET
        if [ -z "$TARGET" ]; then
            echo -e "${RED}No file provided. Exiting.${NC}"
            exit 1
        fi
        echo ""
        echo -e "${GREEN}Running aggressive audit on $TARGET...${NC}"
        echo ""
        node bin/codex-sol.js audit -t "$TARGET" --aggressive --authorize --llm --reasoning-effort xhigh
        ;;
    4)
        node bin/codex-sol.js list
        ;;
    5)
        echo ""
        echo -e "${CYAN}Starting Codex CLI session...${NC}"
        echo -e "${YELLOW}Make sure you've run 'codex login' first${NC}"
        echo ""
        codex
        ;;
    *)
        echo -e "${RED}Invalid choice. Exiting.${NC}"
        exit 1
        ;;
esac
