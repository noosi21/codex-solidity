#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# Codex Solidity — Kali Linux Setup Script
# Installs all dependencies for professional smart contract auditing
# ═══════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "  ██████╗ ██████╗ ███████╗███████╗██╗  ██╗██╗███████╗██████╗ ██╗     ██╗███████╗██████╗"
echo "  ██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██║██╔════╝██╔══██╗██║     ██║██╔════╝██╔══██╗"
echo "  ██║   ██║██║  ██║███████╗███████╗███████║██║█████╗  ██████╔╝██║     ██║█████╗  ██████╔╝"
echo "  ██║   ██║██║  ██║╚════██║╚════██║██╔══██║██║██╔══╝  ██╔══██╗██║     ██║██╔══╝  ██╔══██╗"
echo "  ╚██████╔╝██████╔╝███████║███████║██║  ██║██║███████╗██║  ██║███████╗██║███████╗██║  ██║"
echo "   ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝╚══════╝╚═╝  ╚═╝"
echo ""
echo "  ⛓️  Kali Linux Setup — Smart Contract Audit Workstation"
echo ""

# ─── 1. System Dependencies ───
echo -e "${CYAN}[1/7]${NC} Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq git curl wget nodejs npm python3 python3-pip 2>/dev/null

# ─── 2. Node.js (v20+) ───
echo -e "${CYAN}[2/7]${NC} Setting up Node.js 20.x..."
if ! command -v node &> /dev/null || [[ "$(node -v | cut -d'v' -f2 | cut -d'.' -f1)" -lt 20 ]]; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 2>/dev/null
    sudo apt-get install -y nodejs 2>/dev/null
fi
echo -e "  Node.js: ${GREEN}$(node -v)${NC}"
echo -e "  npm:     ${GREEN}$(npm -v)${NC}"

# ─── 3. Foundry (Forge, Cast, Anvil, Chisel) ───
echo -e "${CYAN}[3/7]${NC} Installing Foundry..."
if ! command -v forge &> /dev/null; then
    curl -L https://foundry.paradigm.xyz | bash 2>/dev/null
    source ~/.bashrc 2>/dev/null || true
    forge install 2>/dev/null || true
fi
echo -e "  Forge: ${GREEN}$(forge --version 2>/dev/null || echo 'not found')${NC}"

# ─── 4. Slither (Static Analyzer) ───
echo -e "${CYAN}[4/7]${NC} Installing Slither..."
if ! command -v slither &> /dev/null; then
    pip3 install slither-analyzer 2>/dev/null || pip install slither-analyzer 2>/dev/null || true
fi
echo -e "  Slither: ${GREEN}$(slither --version 2>/dev/null || echo 'not found')${NC}"

# ─── 5. Echidna (Fuzzer) ───
echo -e "${CYAN}[5/7]${NC} Installing Echidna..."
if ! command -v echidna &> /dev/null; then
    wget -q https://github.com/crytic/echidna/releases/latest/download/echidna-linux-x86_64.tar.gz -O /tmp/echidna.tar.gz 2>/dev/null
    if [ -f /tmp/echidna.tar.gz ]; then
        sudo tar -xzf /tmp/echidna.tar.gz -C /usr/local/bin/ echidna 2>/dev/null || true
        rm /tmp/echidna.tar.gz 2>/dev/null
    fi
fi
echo -e "  Echidna: ${GREEN}$(echidna --version 2>/dev/null || echo 'not found — install manually')${NC}"

# ─── 6. Codex Solidity ───
echo -e "${CYAN}[6/7]${NC} Installing Codex Solidity..."
if [ ! -d "$HOME/codex-solidity" ]; then
    git clone https://github.com/noosi21/codex-solidity.git "$HOME/codex-solidity"
fi
cd "$HOME/codex-solidity"
npm install --silent 2>/dev/null
echo -e "  Codex Solidity: ${GREEN}installed${NC}"

# ─── 7. OpenAI API Key ───
echo -e "${CYAN}[7/7]${NC} Configuring LLM access..."
if [ -z "$OPENAI_API_KEY" ]; then
    echo -e "  ${YELLOW}OPENAI_API_KEY not set.${NC}"
    echo -ne "  Enter your OpenAI API key (or press Enter to skip): "
    read -r API_KEY
    if [ -n "$API_KEY" ]; then
        echo "export OPENAI_API_KEY=\"$API_KEY\"" >> ~/.bashrc
        export OPENAI_API_KEY="$API_KEY"
        echo -e "  ${GREEN}API key saved to ~/.bashrc${NC}"
    else
        echo -e "  ${YELLOW}Skipped — set OPENAI_API_KEY later to enable LLM reasoning${NC}"
    fi
else
    echo -e "  OPENAI_API_KEY: ${GREEN}already set${NC}"
fi

# ─── Done ───
echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ Setup Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Quick Start:${NC}"
echo ""
echo "  # Audit a local project:"
echo "  node ~/codex-solidity/bin/codex-sol.js audit -t ./contracts/"
echo ""
echo "  # Audit a GitHub repo directly:"
echo "  node ~/codex-solidity/bin/codex-sol.js audit -t https://github.com/org/repo"
echo ""
echo "  # Audit with GPT-5.4 xhigh reasoning:"
echo "  node ~/codex-solidity/bin/codex-sol.js audit -t https://github.com/org/repo --llm --reasoning-effort xhigh"
echo ""
echo "  # Audit specific subdirectory on GitHub:"
echo "  node ~/codex-solidity/bin/codex-sol.js audit -t https://github.com/org/repo/tree/main/contracts --llm"
echo ""
echo "  # Run individual analysis modules:"
echo "  node ~/codex-solidity/bin/codex-sol.js symbolic -t ./contracts/"
echo "  node ~/codex-solidity/bin/codex-sol.js invariant -t ./contracts/"
echo "  node ~/codex-solidity/bin/codex-sol.js fuzz -t ./contracts/"
echo "  node ~/codex-solidity/bin/codex-sol.js cross-contract -t ./contracts/"
echo ""
echo -e "  ${YELLOW}Set OPENAI_API_KEY to unlock GPT-5.4 xhigh deep reasoning${NC}"
echo ""
