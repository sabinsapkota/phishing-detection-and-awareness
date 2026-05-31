#!/bin/bash

echo "==================================="
echo "  PhishGuard - Starting Server"
echo "==================================="

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -q -r requirements.txt

# Initialize database if not exists
if [ ! -f "phishing.db" ]; then
    echo "Initializing database..."
    python -c "from app import app, db; app.app_context().push(); db.create_all()"
    echo "Database created."
fi

# Create demo data
echo "Setting up demo data..."
python demo_data.py

echo ""
echo "==================================="
echo "  Starting Flask Server"
echo "==================================="
echo "Access the application at: http://localhost:5000"
echo ""
echo "Default Admin Login:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "Demo User Login:"
echo "  Username: user_it_1"
echo "  Password: password123"
echo "==================================="

python app.py
