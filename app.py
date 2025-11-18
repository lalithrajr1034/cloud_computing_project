from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
from werkzeug.utils import secure_filename
import os
import hashlib
from cryptography.fernet import Fernet
import base64
from datetime import datetime, timedelta
import humanize

from config import Config
from database import Database

app = Flask(__name__)
app.config.from_object(Config)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db = Database()

# Helper functions
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_key():
    return Fernet.generate_key()

def get_fernet(user_id):
    """Get Fernet instance for user encryption"""
    result = db.execute_query(
        "SELECT encryption_key FROM users WHERE id = %s",
        (user_id,),
        fetch=True
    )
    if result:
        return Fernet(result[0]['encryption_key'].encode())
    return None

def get_user_files(user_id):
    """Get all files for a user"""
    return db.execute_query(
        """SELECT id, filename, file_size, file_type, upload_date 
           FROM files WHERE user_id = %s ORDER BY upload_date DESC""",
        (user_id,),
        fetch=True
    )

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('register.html')
        
        # Hash password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        # Generate encryption key for user
        encryption_key = generate_key().decode()
        
        # Insert user into database
        result = db.execute_query(
            "INSERT INTO users (username, password, encryption_key) VALUES (%s, %s, %s)",
            (username, hashed_password, encryption_key)
        )
        
        if result:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username already exists!', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        user = db.execute_query(
            "SELECT id, username FROM users WHERE username = %s AND password = %s",
            (username, hashed_password),
            fetch=True
        )
        
        if user:
            session['user_id'] = user[0]['id']
            session['username'] = user[0]['username']
            session.permanent = True
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    files = get_user_files(session['user_id'])
    
    # Format file sizes and dates
    for file in files:
        if file['file_size']:
            file['formatted_size'] = humanize.naturalsize(file['file_size'])
        file['formatted_date'] = file['upload_date'].strftime('%Y-%m-%d %H:%M:%S')
    
    # Calculate storage usage
    total_size = sum(file['file_size'] or 0 for file in files)
    
    return render_template('dashboard.html', 
                         files=files, 
                         username=session['username'],
                         total_size=humanize.naturalsize(total_size),
                         file_count=len(files))

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    if 'file' not in request.files:
        flash('No file selected!', 'error')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected!', 'error')
        return redirect(url_for('dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        user_fernet = get_fernet(session['user_id'])
        
        if user_fernet:
            # Get file info
            file_data = file.read()
            file_size = len(file_data)
            file_type = file.content_type or 'application/octet-stream'
            
            # Encrypt file content
            encrypted_data = user_fernet.encrypt(file_data)
            
            # Save encrypted file
            encrypted_filename = hashlib.sha256(f"{filename}{datetime.now().timestamp()}".encode()).hexdigest() + '.enc'
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save file info to database
            result = db.execute_query(
                """INSERT INTO files (user_id, filename, encrypted_filename, file_size, file_type) 
                   VALUES (%s, %s, %s, %s, %s)""",
                (session['user_id'], filename, encrypted_filename, file_size, file_type)
            )
            
            if result:
                flash('File uploaded successfully!', 'success')
            else:
                flash('Error uploading file!', 'error')
        else:
            flash('Encryption error!', 'error')
    else:
        flash('File type not allowed!', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
def download_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    file_info = db.execute_query(
        """SELECT filename, encrypted_filename FROM files 
           WHERE id = %s AND user_id = %s""",
        (file_id, session['user_id']),
        fetch=True
    )
    
    if file_info:
        filename = file_info[0]['filename']
        encrypted_filename = file_info[0]['encrypted_filename']
        user_fernet = get_fernet(session['user_id'])
        
        if user_fernet:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            
            if os.path.exists(file_path):
                # Decrypt file
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
                
                try:
                    decrypted_data = user_fernet.decrypt(encrypted_data)
                    
                    # Create temporary file for download
                    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + filename)
                    with open(temp_path, 'wb') as f:
                        f.write(decrypted_data)
                    
                    response = send_file(temp_path, as_attachment=True, download_name=filename)
                    
                    # Clean up temporary file after request
                    @response.call_on_close
                    def cleanup():
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                    
                    return response
                
                except Exception as e:
                    flash('Error decrypting file!', 'error')
    
    flash('File not found!', 'error')
    return redirect(url_for('dashboard'))

@app.route('/delete/<int:file_id>')
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    file_info = db.execute_query(
        """SELECT encrypted_filename FROM files 
           WHERE id = %s AND user_id = %s""",
        (file_id, session['user_id']),
        fetch=True
    )
    
    if file_info:
        encrypted_filename = file_info[0]['encrypted_filename']
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        
        # Delete file from filesystem
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete file record from database
        db.execute_query("DELETE FROM files WHERE id = %s", (file_id,))
        flash('File deleted successfully!', 'success')
    else:
        flash('File not found!', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/api/files')
def api_files():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    files = get_user_files(session['user_id'])
    return jsonify(files)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_info = db.execute_query(
        "SELECT username, created_at FROM users WHERE id = %s",
        (session['user_id'],),
        fetch=True
    )
    
    files = get_user_files(session['user_id'])
    total_size = sum(file['file_size'] or 0 for file in files)
    
    return render_template('profile.html',
                         user_info=user_info[0] if user_info else None,
                         file_count=len(files),
                         total_size=humanize.naturalsize(total_size))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out!', 'info')
    return redirect(url_for('index'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.execute_query("ROLLBACK")
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Initialize database connection
    if db.init_db():
        print("MySQL database connection established successfully")
        app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        print("Failed to connect to MySQL database")