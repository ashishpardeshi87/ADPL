#!/bin/bash

# Hoax Threat Detection System - Setup Script

echo "================================================"
echo "Hoax Threat Detection System - Installation"
echo "================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
python_version=$(python3 --version 2>&1 | grep -Po '(?<=Python )\d+\.\d+')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then 
    echo -e "${GREEN}✓ Python $python_version is installed${NC}"
else
    echo -e "${RED}✗ Python 3.8+ is required. Current version: $python_version${NC}"
    exit 1
fi

# Create virtual environment
echo -e "${YELLOW}Creating virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate
echo -e "${GREEN}✓ Virtual environment created${NC}"

# Upgrade pip
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip

# Install dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
pip install -r requirements.txt
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Download NLP models
echo -e "${YELLOW}Downloading NLP models...${NC}"
python -m spacy download en_core_web_sm
python -m spacy download en_core_web_lg
python -c "import nltk; nltk.download('punkt'); nltk.download('stopwords'); nltk.download('vader_lexicon')"
echo -e "${GREEN}✓ NLP models downloaded${NC}"

# Create necessary directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p logs data/models config
echo -e "${GREEN}✓ Directories created${NC}"

# Copy configuration files
echo -e "${YELLOW}Setting up configuration...${NC}"
if [ ! -f config/config.yaml ]; then
    cp config/config.yaml.example config/config.yaml 2>/dev/null || echo "config.yaml.example not found"
fi

if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${YELLOW}Please edit .env file with your API keys and credentials${NC}"
fi
echo -e "${GREEN}✓ Configuration files created${NC}"

# Check for required services
echo -e "${YELLOW}Checking required services...${NC}"

# Check PostgreSQL
if command -v psql &> /dev/null; then
    echo -e "${GREEN}✓ PostgreSQL is installed${NC}"
else
    echo -e "${YELLOW}⚠ PostgreSQL not found. Please install PostgreSQL${NC}"
fi

# Check Redis
if command -v redis-cli &> /dev/null; then
    echo -e "${GREEN}✓ Redis is installed${NC}"
else
    echo -e "${YELLOW}⚠ Redis not found. Please install Redis${NC}"
fi

# Download GeoIP database (optional)
echo -e "${YELLOW}GeoIP Database Setup${NC}"
echo "To enable IP geolocation, download the GeoLite2-City database from MaxMind:"
echo "1. Sign up at https://www.maxmind.com/en/geolite2/signup"
echo "2. Download GeoLite2-City.mmdb"
echo "3. Place it in data/GeoLite2-City.mmdb"

echo ""
echo "================================================"
echo -e "${GREEN}Setup Complete!${NC}"
echo "================================================"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your API credentials"
echo "2. Edit config/config.yaml for system configuration"
echo "3. Set up PostgreSQL database:"
echo "   createdb threat_detection"
echo "4. Start Redis server:"
echo "   redis-server"
echo "5. Run the application:"
echo "   python main.py --mode both"
echo ""
echo "For Docker deployment:"
echo "   docker-compose up -d"
echo ""
echo -e "${GREEN}Happy threat hunting!${NC}"