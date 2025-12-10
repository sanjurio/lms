# Erlang Systems LMS

## Overview
A comprehensive Learning Management System (LMS) for Enterprise Erlang/OTP development training designed for telecom and distributed systems. The platform features domain-based access control, course management, user progress tracking, forum discussions, and document analysis capabilities.

## Recent Changes (December 10, 2025)
- **Email Verification for Registration**: Added email OTP verification during registration
  - Users must verify their email address before proceeding to 2FA setup
  - Prevents fake/dummy account creation
  - 6-digit OTP sent to email with 10-minute expiry
  - Resend verification code option available
  - EmailVerificationToken model stores pending registrations

- **7-Day Mandatory Course Reminders**: Automated reminder system for approaching deadlines
  - Admin can manually trigger reminders from Mandatory Courses page
  - Sends urgent reminder emails to users with courses due within 7 days
  - Only sends to users who haven't completed the course
  - Tracks sent reminders to avoid duplicate emails
  - MandatoryCourseReminder model for tracking sent notifications

- **Inline Media Embedding**: Enhanced lesson editor with inline media insertion
  - Added toolbar buttons to insert YouTube, OneDrive/external videos, files, and links directly in content
  - Media can now be placed anywhere in the lesson (topics → video → topics → file pattern)
  - Modal dialogs for entering YouTube URLs, embed codes, file selections, and external links
  - Videos display inline where placed with responsive 16:9 aspect ratio
  - File download links styled as interactive cards
  - Auto-increment lesson order when adding new lessons
  - After creating a lesson, redirects to edit page to immediately add media

- **Multi-Media Lesson Support**: Comprehensive media management for lessons
  - LessonMedia model for storing YouTube videos, uploaded files, and external links
  - Admin UI with tabs for managing media (YouTube URLs with + button, file uploads, external links)
  - User lesson view displays all media types with proper categorization
  - Access control enforced: YouTube videos only visible to users with video permissions, files/links require text permissions
  - Support for OneDrive, Google Drive, Dropbox links as external resources

## Previous Changes (December 9, 2025)
- **Fixed Course Deletion Errors**: Added proper cascade cleanup for assignments, questions, attempts, and related entities
- **Improved Assignment System**: Assignments now appear as "Final Assessment" at end of courses
  - Users must complete all lessons before taking the final assessment
  - Assignments without questions show "Coming Soon" message
  - Validation prevents starting assignments that have no questions added yet
- **Automatic Admin Creation**: Admin user (admin@example.com / Admin123) is automatically created on app startup if no admin exists

## Changes (December 8, 2025)
- **Course Completion Tracking System**: Implemented comprehensive progress tracking
  - Lesson pages: Added "Mark as Complete/Incomplete" buttons with status display
  - Course pages: Progress bar showing completion percentage and lesson status icons
  - User dashboard: Overall progress card with stats and per-course progress bars
  - Admin user progress page: Detailed view of any user's course completion status
  - Dynamic button text (Start/Continue/Review Course) based on progress

- **Replit Environment Setup**: Configured the application to run in Replit
  - Updated main.py to bind to 0.0.0.0:5000 for frontend access
  - Configured PostgreSQL database using Replit's built-in database
  - Set up Flask workflow for development server
  - Configured deployment with gunicorn for autoscale production deployment
  - Installed all required dependencies including Flask, SQLAlchemy, NLTK, and document processing libraries

## Project Architecture

### Technology Stack
- **Backend**: Flask 3.1.0 with Python 3.x
- **Database**: PostgreSQL (Replit-managed) with SQLAlchemy ORM
- **Authentication**: Flask-Login with 2FA support (PyOTP, QR codes)
- **Forms & Security**: Flask-WTF with CSRF protection
- **Document Processing**: NLTK, PyPDF2, python-docx for document analysis
- **Frontend**: HTML templates with Jinja2, vanilla JavaScript, CSS

### Key Features
1. **Domain-Based Access Control**
   - THBS employees: Full access to video and text content
   - BT employees: Text content only
   - Admin approval required for all new users

2. **Course Management**
   - Hierarchical course structure (Courses → Lessons)
   - User interests and interest-based course access
   - Progress tracking per lesson
   - Bookmarking and activity logging

3. **Forum System**
   - Course-specific forums
   - Topic creation and discussions
   - User engagement tracking

4. **Document Analysis**
   - Upload and analyze PDFs and DOCX files
   - NLTK-powered text analysis
   - Support for technical documentation

5. **Two-Factor Authentication**
   - Optional 2FA for enhanced security
   - QR code generation for authenticator apps

### Database Schema
Key models:
- **User**: Authentication, access levels, 2FA
- **Course**: Training courses with metadata
- **Lesson**: Individual lessons within courses
- **Interest**: Topic areas (Erlang, OTP, Telecom, etc.)
- **Forum/Topic/Post**: Discussion system
- **UserLessonProgress**: Lesson completion tracking
- **UserActivity**: Activity logging

### Directory Structure
```
app/
├── static/         # CSS, JS, images
├── templates/      # Jinja2 templates (admin, auth, user, forum, errors)
├── utils/          # Helper modules (admin, auth, course helpers)
├── __init__.py     # App factory with database and extension setup
├── config.py       # Configuration (environment-based)
├── forms.py        # WTForms definitions
├── models.py       # SQLAlchemy models
├── routes.py       # Flask route handlers
└── document_analysis.py  # Document processing logic
```

### Environment Variables
- `DATABASE_URL`: PostgreSQL connection string (auto-configured by Replit)
- `SESSION_SECRET`: Flask session secret key (configured as Replit secret)
- `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`: Database credentials (auto-configured)
- `SMTP_USER`: Gmail address for sending emails (required for email features)
- `SMTP_PASSWORD`: Gmail App Password (required for email features)
- `SMTP_HOST`: SMTP server host (default: smtp.gmail.com)
- `SMTP_PORT`: SMTP server port (default: 587)
- `SMTP_FROM_EMAIL`: Email sender address (defaults to SMTP_USER)

### Deployment
- **Development**: Flask dev server on port 5000 (workflow: `python main.py`)
- **Production**: Gunicorn with autoscale deployment
  - Command: `gunicorn --bind=0.0.0.0:$PORT --reuse-port main:app`
  - Deployment type: autoscale (stateless, uses PostgreSQL for persistence)

## Development Notes

### Running Locally
The Flask workflow is configured to run automatically. The application:
1. Creates database tables on startup
2. Downloads required NLTK data (punkt, stopwords, averaged_perceptron_tagger)
3. Serves on 0.0.0.0:5000 with debug mode enabled

### Admin Setup
Use the utility scripts in the project root:
- `create_local_admin.py`: Create an admin user
- `reset_admin_2fa.py`: Reset 2FA for admin users
- `create_test_courses.py`: Populate test data
- `setup_db.py`: Initialize database schema

### Access Control Configuration
Edit `app/config.py` to modify domain-based access rules:
```python
DOMAIN_ACCESS = {
    'thbs.com': {'access_level': 'full_access', ...},
    'bt.com': {'access_level': 'text_only', ...}
}
```

### Database
- PostgreSQL is used for both development and production
- SQLAlchemy handles migrations via `db.create_all()` on startup
- Connection pooling configured with health checks

## User Preferences
None specified yet.

## Next Steps
- Set up admin user account for initial access
- Populate course content and lessons
- Configure additional email domains for access control
- Review and test document analysis features
- Add comprehensive error handling and logging
