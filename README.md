# Make setup script executable
chmod +x setup.sh

# Run setup
./setup.sh

# Install Python dependencies
pip3 install -r requirements.txt

# Run the application
python3 app.py

