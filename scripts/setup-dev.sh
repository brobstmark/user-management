#!/bin/bash
echo "Setting up development environment..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements-dev.txt

echo "Development environment setup complete!"
echo "Run 'source venv/bin/activate' to activate the virtual environment"
echo "Run 'scripts/start-dev.sh' to start the development server"
