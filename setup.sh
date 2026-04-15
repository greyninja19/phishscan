#!/usr/bin/env bash
# PhishScan Pro - Kali Linux setup script
set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ____  _     _     _     ____                  ____            "
echo " |  _ \| |__ (_)___| |__ / ___|  ___ __ _ _ __ |  _ \ _ __ ___ "
echo " | |_) | '_ \| / __| '_ \\___ \ / __/ _\` | '_ \| |_) | '__/ _ \\"
echo " |  __/| | | | \__ \ | | |___) | (_| (_| | | | |  __/| | | (_) |"
echo " |_|   |_| |_|_|___/_| |_|____/ \___\__,_|_| |_|_|   |_|  \___/"
echo -e "${NC}"
echo -e "${YELLOW}  Advanced Phishing URL Detector — Kali Linux Setup${NC}"
echo ""

# Create directories
mkdir -p phishscan/static

# Install system dependencies
echo -e "${GREEN}[1/3] Installing system packages...${NC}"
sudo apt-get update -qq
sudo apt-get install -y python3-pip python3-venv libssl-dev

# Create and activate virtual environment
echo -e "${GREEN}[2/3] Setting up Python virtual environment...${NC}"
python3 -m venv phishscan/venv
source phishscan/venv/bin/activate

# Install Python dependencies
echo -e "${GREEN}[3/3] Installing Python dependencies...${NC}"
pip install -q --upgrade pip
pip install -q flask requests python-whois dnspython tldextract colorama

echo ""
echo -e "${GREEN}✓ Setup complete!${NC}"
echo ""
echo "  Run web interface:   source phishscan/venv/bin/activate && python phishscan/app.py"
echo "  Run CLI scan:        source phishscan/venv/bin/activate && python phishscan/app.py <URL>"
echo ""
