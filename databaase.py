import mysql.connector
from mysql.connector import Error
from config import Config
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        self.config = {
            'host': Config.MYSQL_HOST,
            'user': Config.MYSQL_USER,
            'password': Config.MYSQL_PASSWORD,
            'database': Config.MYSQL_DB,
            'port': Config.MYSQL_PORT,
            'charset': 'utf8mb4',
            'collation': 'utf8mb4_unicode_ci'
        }
    
    def get_connection(self):
        """Create and return database connection"""
        try:
            connection = mysql.connector.connect(**self.config)
            if connection.is_connected():
                return connection
        except Error as e:
            logger.error(f"Error connecting to MySQL: {e}")
            return None
    
    def execute_query(self, query, params=None, fetch=False):
        """Execute SQL query and return results if fetch=True"""
        connection = self.get_connection()
        if not connection:
            return None
        
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute(query, params or ())
            
            if fetch:
                result = cursor.fetchall()
            else:
                connection.commit()
                result = cursor.lastrowid
            
            cursor.close()
            connection.close()
            return result
        
        except Error as e:
            logger.error(f"Error executing query: {e}")
            connection.rollback()
            connection.close()
            return None
    
    def init_db(self):
        """Initialize database with required tables"""
        try:
            # Test connection
            connection = self.get_connection()
            if connection:
                logger.info("MySQL database connection successful")
                connection.close()
                return True
            return False
        except Error as e:
            logger.error(f"Database initialization failed: {e}")
            return False