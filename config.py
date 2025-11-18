import os
from datetime import timedelta

class Config:
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here-change-in-production'
    
    # MySQL Configuration
    MYSQL_HOST = os.environ.get('MYSQL_HOST') or 'localhost'
    MYSQL_USER = os.environ.get('MYSQL_USER') or 'cloud_user'
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD') or 'secure_password'
    MYSQL_DB = os.environ.get('MYSQL_DB') or 'raspberry_cloud'
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT') or 3306)
    
    # File Upload Configuration
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
    
    # Session Configuration
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    
    # Encryption Configuration
    ENCRYPTION_ALGORITHM = 'fernet'