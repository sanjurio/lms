# Learning Platform

A Learning Management System built with Flask for enterprise training.

## Overview

This is a web-based Learning Management System (LMS) designed for enterprise training. It supports user registration, authentication (with optional 2FA), course management, document analysis, and domain-based access control.

## Tech Stack

- **Backend**: Python 3.11, Flask
- **Database**: PostgreSQL (via SQLAlchemy ORM)
- **Authentication**: Flask-Login with optional TOTP 2FA
- **Task Scheduling**: APScheduler for background tasks (reminders)
- **Document Processing**: NLTK, PyPDF2, python-docx

## Project Structure

```
├── app/
│   ├── __init__.py      # App factory and extensions
│   ├── config.py        # Configuration settings
│   ├── models.py        # Database models
│   ├── routes.py        # Route handlers
│   ├── forms.py         # WTForms definitions
│   ├── document_analysis.py  # Document processing
│   └── templates/       # Jinja2 templates
├── main.py              # Application entry point
├── utils.py             # Utility functions
├── setup_db.py          # Database setup scripts
└── pyproject.toml       # Python dependencies
```

## Running the Application

Development server runs on port 5000 with the workflow command:
```
python main.py
```

## Production Deployment

Uses gunicorn for production:
```
gunicorn --bind=0.0.0.0:5000 --reuse-port main:app
```

## Default Admin

- Email: admin@example.com
- Password: Admin123

## Domain Access Control

The system supports domain-based access control:
- `thbs.com`: Full access (video and text content)
- `bt.com`: Text-only access
