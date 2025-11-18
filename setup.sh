#!/bin/bash

echo "Setting up Raspberry Pi Cloud with MySQL..."

# Update system
sudo apt update
sudo apt upgrade -y

# Install MySQL Server
sudo apt install mysql-server -y

# Install Python and pip
sudo apt install python3 python3-pip -y

# Install required Python packages
pip3 install -r requirements.txt

# Secure MySQL installation
sudo mysql_secure_installation

# Create database and user
sudo mysql -e "CREATE DATABASE IF NOT EXISTS raspberry_cloud;"
sudo mysql -e "CREATE USER IF NOT EXISTS 'cloud_user'@'localhost' IDENTIFIED BY 'secure_password';"
sudo mysql -e "GRANT ALL PRIVILEGES ON raspberry_cloud.* TO 'cloud_user'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

echo "Setup completed successfully!"
echo "Please update the .env file with your MySQL credentials"
echo "Then run: python3 app.py"