#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

check() { echo -e "${GREEN}✔ $1 found:${NC} $2"; }
missing() { echo -e "${RED}✘ $1 not found — installing...${NC}"; }

OS=$(uname -s)

install_package() {
  if [[ "$OS" == "Linux" ]]; then
    sudo apt-get install -y "$1"
  elif [[ "$OS" == "Darwin" ]]; then
    brew install "$1"
  fi
}

echo "================================================"
echo "   Checking Required Tools"
echo "================================================"

# ── Python 3.11+ ──────────────────────────────────
if command -v python3 &>/dev/null; then
  VER=$(python3 --version)
  check "Python" "$VER"
else
  missing "Python"
  if [[ "$OS" == "Linux" ]]; then
    sudo apt-get update && sudo apt-get install -y python3.11
  elif [[ "$OS" == "Darwin" ]]; then
    brew install python@3.11
  fi
fi

# ── Node.js 20+ ───────────────────────────────────
if command -v node &>/dev/null; then
  VER=$(node --version)
  check "Node.js" "$VER"
else
  missing "Node.js"
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

# ── Docker ────────────────────────────────────────
if command -v docker &>/dev/null; then
  VER=$(docker --version)
  check "Docker" "$VER"
else
  missing "Docker"
  if [[ "$OS" == "Linux" ]]; then
    curl -fsSL https://get.docker.com | sudo sh
    sudo usermod -aG docker "$USER"
    echo -e "${YELLOW}⚠ Log out and back in for Docker group permissions to apply.${NC}"
  elif [[ "$OS" == "Darwin" ]]; then
    echo -e "${YELLOW}Please install Docker Desktop from https://www.docker.com/products/docker-desktop${NC}"
  fi
fi

# ── AWS CLI v2 ────────────────────────────────────
if command -v aws &>/dev/null; then
  VER=$(aws --version)
  check "AWS CLI" "$VER"
else
  missing "AWS CLI"
  if [[ "$OS" == "Linux" ]]; then
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
    unzip /tmp/awscliv2.zip -d /tmp
    sudo /tmp/aws/install
    rm -rf /tmp/aws /tmp/awscliv2.zip
  elif [[ "$OS" == "Darwin" ]]; then
    curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o /tmp/AWSCLIV2.pkg
    sudo installer -pkg /tmp/AWSCLIV2.pkg -target /
  fi
fi

# ── Git ───────────────────────────────────────────
if command -v git &>/dev/null; then
  VER=$(git --version)
  check "Git" "$VER"
else
  missing "Git"
  install_package git
fi

# ── Terraform 1.5+ (direct binary install — most reliable) ───────────────────
if command -v terraform &>/dev/null; then
  VER=$(terraform --version | head -1)
  check "Terraform" "$VER"
else
  missing "Terraform"
  if [[ "$OS" == "Linux" ]]; then
    echo -e "${YELLOW}→ Installing Terraform via direct binary download...${NC}"

    # Get latest 1.5+ version (pinned to stable)
    TF_VERSION="1.7.5"
    TF_ZIP="terraform_${TF_VERSION}_linux_amd64.zip"
    TF_URL="https://releases.hashicorp.com/terraform/${TF_VERSION}/${TF_ZIP}"

    echo "→ Downloading Terraform ${TF_VERSION}..."
    curl -fSL "$TF_URL" -o "/tmp/${TF_ZIP}"

    if [[ $? -ne 0 ]]; then
      echo -e "${RED}✘ Download failed. Check your internet connection.${NC}"
      exit 1
    fi

    echo "→ Extracting..."
    sudo apt-get install -y unzip 2>/dev/null
    unzip -o "/tmp/${TF_ZIP}" -d /tmp/terraform_bin

    echo "→ Moving binary to /usr/local/bin..."
    sudo mv /tmp/terraform_bin/terraform /usr/local/bin/terraform
    sudo chmod +x /usr/local/bin/terraform

    # Cleanup
    rm -rf "/tmp/${TF_ZIP}" /tmp/terraform_bin

    # Verify
    if command -v terraform &>/dev/null; then
      echo -e "${GREEN}✔ Terraform installed:$(terraform --version | head -1)${NC}"
    else
      echo -e "${RED}✘ Terraform install failed. Try manually: https://developer.hashicorp.com/terraform/install${NC}"
    fi

  elif [[ "$OS" == "Darwin" ]]; then
    echo -e "${YELLOW}→ Installing Terraform via Homebrew...${NC}"
    brew tap hashicorp/tap
    brew install hashicorp/tap/terraform

    if [[ $? -ne 0 ]]; then
      echo -e "${YELLOW}→ Brew failed, trying direct binary...${NC}"
      TF_VERSION="1.7.5"
      curl -fSL "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_darwin_amd64.zip" -o /tmp/tf.zip
      unzip -o /tmp/tf.zip -d /tmp/terraform_bin
      sudo mv /tmp/terraform_bin/terraform /usr/local/bin/terraform
      sudo chmod +x /usr/local/bin/terraform
      rm -rf /tmp/tf.zip /tmp/terraform_bin
    fi
  fi
fi

echo ""
echo "================================================"
echo "   Final Verification"
echo "================================================"
for cmd in python3 node docker aws git terraform; do
  if command -v $cmd &>/dev/null; then
    echo -e "${GREEN}✔ $cmd${NC}"
  else
    echo -e "${RED}✘ $cmd — manual install may be needed${NC}"
  fi
done
