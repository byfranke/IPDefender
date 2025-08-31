#!/bin/bash

# Update package list and install necessary packages
sudo apt update
sudo apt install -y python3-pip python3-venv

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install required packages
pip install -r requirements.txt

# Run database migrations
python scripts/migrate.py

# Seed the database with initial data
python scripts/seed_data.py

echo "Setup completed successfully."