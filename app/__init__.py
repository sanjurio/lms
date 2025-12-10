import os
import logging
import atexit
from datetime import datetime
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler
from .config import Config

scheduler = BackgroundScheduler(daemon=True)

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.debug("Starting Learning Management System")

# Create base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Initialize other extensions
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(Config)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    # Configure the database
    database_url = app.config['DATABASE_URL']
    if 'sqlite' in database_url.lower():
        logger.info("Using SQLite database for local development")
    else:
        logger.info(f"Using database: {database_url.split('@')[0].split('://')[0]}://...")
    
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    
    # Configure login manager
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'

    with app.app_context():
        # Import models to create tables
        from . import models
        db.create_all()
        logger.info("Database tables created successfully")
        
        # Download NLTK data for document analysis
        try:
            import nltk
            logger.info("Downloading NLTK data for document analysis...")
            nltk.download('punkt', quiet=True)
            nltk.download('stopwords', quiet=True) 
            nltk.download('wordnet', quiet=True)
            logger.info("Downloaded NLTK resource: punkt")
            logger.info("Downloaded NLTK resource: stopwords")
            logger.info("Downloaded NLTK resource: wordnet")
        except Exception as e:
            logger.warning(f"Could not download NLTK data: {e}")

        # Import and register routes
        from . import routes
        routes.register_routes(app)
        logger.debug("Routes imported successfully")
        
        # Register CSRF error handler
        from flask_wtf.csrf import CSRFError
        from flask import flash, redirect, request, url_for
        from urllib.parse import urlparse
        
        @app.errorhandler(CSRFError)
        def handle_csrf_error(e):
            flash('Your session has expired. Please try again.', 'warning')
            # Safe redirect - validate referrer is from same host
            referrer = request.referrer
            if referrer:
                parsed = urlparse(referrer)
                # Only allow redirect to same host
                if parsed.netloc == '' or parsed.netloc == request.host:
                    return redirect(referrer)
            # Fall back to index page
            return redirect(url_for('index'))
        
        # Create default admin user if it doesn't exist
        from .models import User
        from werkzeug.security import generate_password_hash
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash("Admin123"),
                is_admin=True,
                is_approved=True,
                is_2fa_enabled=False
            )
            db.session.add(admin)
            db.session.commit()
            logger.info("Default admin user created (admin@example.com / Admin123)")
        
        # Register context processors
        register_context_processors(app)
        
        # Start the background scheduler for automatic reminders
        start_reminder_scheduler(app)

    return app


def start_reminder_scheduler(app):
    """Start the background scheduler for automatic mandatory course reminders
    
    Note: The check_and_send_mandatory_course_reminders function uses the 
    MandatoryCourseReminder table to track sent reminders, preventing duplicate
    emails even if the job runs from multiple workers.
    """
    global scheduler
    
    def run_reminder_check():
        """Run the reminder check within app context"""
        with app.app_context():
            try:
                from .routes import check_and_send_mandatory_course_reminders
                reminders_sent = check_and_send_mandatory_course_reminders()
                if reminders_sent > 0:
                    logger.info(f"Automatic scheduler: Sent {reminders_sent} mandatory course reminder(s)")
                else:
                    logger.debug("Automatic scheduler: No reminders to send")
            except Exception as e:
                logger.error(f"Error in automatic reminder scheduler: {e}")
    
    if not scheduler.running:
        scheduler.add_job(
            func=run_reminder_check,
            trigger='cron',
            hour=8,
            minute=0,
            id='mandatory_course_reminders',
            name='Send mandatory course reminders 7 days before deadline',
            replace_existing=True,
            misfire_grace_time=3600
        )
        scheduler.start()
        logger.info("Background scheduler started - will check for mandatory course reminders daily at 8:00 AM UTC")
        
        atexit.register(lambda: scheduler.shutdown(wait=False))

# Template context processors
def inject_now():
    return {'now': datetime.utcnow()}

def register_context_processors(app):
    """Register template context processors"""
    @app.context_processor
    def utility_processor():
        return {'now': datetime.utcnow()}

# Error handlers
def page_not_found(e):
    return render_template('errors/404.html'), 404

def internal_server_error(e):
    return render_template('errors/500.html'), 500