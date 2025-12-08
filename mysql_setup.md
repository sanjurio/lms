
# MySQL Setup Instructions

## Prerequisites
- MySQL 8.4.4 installed
- VS Code with MySQL extensions
- Python with required packages

## Steps to Switch to MySQL

### 1. Install MySQL Python Driver
```bash
pip install PyMySQL mysql-connector-python
```

### 2. Update Database Configuration
Edit `app/config.py` to use MySQL instead of SQLite:

```python
import os

class Config:
    # MySQL Database Configuration
    MYSQL_HOST = os.environ.get('MYSQL_HOST') or 'localhost'
    MYSQL_USER = os.environ.get('MYSQL_USER') or 'root'
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD') or 'your_password'
    MYSQL_DB = os.environ.get('MYSQL_DB') or 'erlang_lms'
    
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}/{MYSQL_DB}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
```

### 3. Create MySQL Database
```sql
CREATE DATABASE erlang_lms CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 4. Set Environment Variables
Create a `.env` file or set these in your environment:
```
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=your_mysql_password
MYSQL_DB=erlang_lms
SECRET_KEY=your-secret-key-here
```

### 5. Run Database Setup
```bash
python setup_db.py
```

### 6. Start the Application
```bash
python main.py
```

## Troubleshooting
- Ensure MySQL service is running
- Check firewall settings for port 3306
- Verify credentials and database exists
- Check MySQL logs for connection issues

## Features Enabled
- THBS users can access video content and "Fun" courses
- BT users can only access text content (Fun courses hidden)
- Empty courses show helpful messages instead of errors
- Lesson navigation with proper access controls
