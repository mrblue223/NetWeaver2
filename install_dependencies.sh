#!/bin/bash

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting setup for NetWeaver Server GUI...${NC}"

# Check if Python is installed
if ! command -v python3 &> /dev/null
then
    echo -e "${RED}Python 3 could not be found. Please install Python 3 to proceed.${NC}"
    exit 1
fi

# Create a virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment 'venv'...${NC}"
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to create virtual environment.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Virtual environment created.${NC}"
else
    echo -e "${YELLOW}Virtual environment 'venv' already exists.${NC}"
fi

# Activate the virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to activate virtual environment.${NC}"
    exit 1
fi
echo -e "${GREEN}Virtual environment activated.${NC}"

# Install dependencies
echo -e "${YELLOW}Installing required Python dependencies...${NC}"
pip install Pillow bcrypt cryptography
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to install dependencies. Please check your internet connection or try again.${NC}"
    deactivate # Deactivate venv on failure
    exit 1
fi
echo -e "${GREEN}All dependencies installed successfully.${NC}"

echo -e "${GREEN}Setup complete.${NC} To run the application, ensure the virtual environment is activated and then run: ${YELLOW}python main.py${NC}"
echo -e "You can activate the virtual environment anytime by running: ${YELLOW}source venv/bin/activate${NC}"

