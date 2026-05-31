#!/bin/bash

echo "==================================="
echo "  PhishGuard - Setup"
echo "==================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    exit 1
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Initialize database
echo "Initializing database..."
python -c "from app import app, db; app.app_context().push(); db.create_all()"

# Create demo data
echo "Setting up demo data..."
python demo_data.py

echo ""
echo "==================================="
echo "  Setup Complete!"
echo "==================================="
echo ""
echo "To start the application, run: ./start.sh"
echo ""
