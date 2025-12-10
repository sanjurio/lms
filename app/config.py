import os

class Config:
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'dev-key-change-in-production')
    
    # Session cookie settings for iframe/proxy environment
    # Use SameSite=None for cross-site iframe contexts, Secure required with SameSite=None
    SESSION_COOKIE_SAMESITE = 'None'
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///lms.db')
    
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