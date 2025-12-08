import os

class Config:
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'dev-key-change-in-production')
    
    # Use SQLite by default since the PostgreSQL credentials are currently invalid
    # To use PostgreSQL, ensure DATABASE_URL points to a valid database
    db_url = os.environ.get('DATABASE_URL')
    if db_url and 'neondb_owner' in db_url:
        # Old/invalid Neon database - use SQLite instead
        DATABASE_URL = 'sqlite:///lms.db'
    else:
        DATABASE_URL = db_url or 'sqlite:///lms.db'
    
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Application settings
    APP_NAME = "Erlang Systems LMS"
    APP_DESCRIPTION = "Learning Management System for Enterprise Erlang Systems Training"
    
    # Email domain access control
    DOMAIN_ACCESS = {
        'thbs.com': {
            'access_level': 'full_access',
            'description': 'THBS employees - Full access to video and text content'
        },
        'bt.com': {
            'access_level': 'text_only', 
            'description': 'BT employees - Text content only'
        }
    }