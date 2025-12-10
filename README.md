# Erlang Systems LMS - Local Development Setup

A Learning Management System for enterprise training, supporting document analysis, video/text courses, mandatory course assignments, and more.

## Prerequisites

- Python 3.11 or higher
- pip (Python package manager)

## Installation

### 1. Clone/Download the Project

Download or clone the project to your local machine.

### 2. Create a Virtual Environment (Recommended)

```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install flask flask-login flask-sqlalchemy flask-wtf apscheduler nltk pillow pypdf2 python-docx qrcode email-validator werkzeug wtforms pyotp sqlalchemy gunicorn
```

Or if you have the pyproject.toml file, you can use:

```bash
pip install -e .
```

**Note:** You do NOT need `psycopg2-binary` for SQLite (it's only needed for PostgreSQL).

## Configuration

### Environment Variables

Create a `.env` file in the project root or set these environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SESSION_SECRET` | No | `dev-key-change-in-production` | Secret key for session management. Set a strong random string in production. |
| `DATABASE_URL` | No | `sqlite:///lms.db` | Database connection string. For SQLite, use `sqlite:///instance/lms.db` |

**For SQLite (Local Development):**

The application defaults to SQLite if no `DATABASE_URL` is set. To store the database in an `instance` directory:

```bash
# On Windows (Command Prompt):
set DATABASE_URL=sqlite:///instance/lms.db

# On Windows (PowerShell):
$env:DATABASE_URL = "sqlite:///instance/lms.db"

# On macOS/Linux:
export DATABASE_URL=sqlite:///instance/lms.db
```

### Create Instance Directory

Create the `instance` directory where SQLite will store the database:

```bash
mkdir instance
```

## Running the Application

### Option 1: Using Flask Development Server

```bash
# Set Flask app
export FLASK_APP=main.py  # (or 'set FLASK_APP=main.py' on Windows)

# Run the development server
flask run --host=0.0.0.0 --port=5000
```

### Option 2: Using Python Directly

```bash
python -c "from app import create_app; app = create_app(); app.run(host='0.0.0.0', port=5000, debug=True)"
```

### Option 3: Using Gunicorn (Production-like, macOS/Linux only)

```bash
gunicorn --bind 0.0.0.0:5000 --reload main:app
```

The application will be available at: **http://localhost:5000**

## Default Admin Account

On first run, the application automatically creates a default admin user:

- **Email:** admin@example.com
- **Password:** Admin123

**Important:** Change these credentials immediately in a production environment.

## Document Analysis Feature

The document analysis feature uses NLTK (Natural Language Toolkit) for text processing. The required NLTK data packages are **automatically downloaded** when the application starts:

- `punkt` - Tokenization
- `stopwords` - Common words filtering
- `wordnet` - Word meanings and synonyms

If you're behind a firewall or the automatic download fails, you can manually download them:

```python
import nltk
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
nltk.download('averaged_perceptron_tagger')
```

The NLTK data will be stored in `~/nltk_data` by default.

## Automatic Reminder Scheduler

The application includes an automatic scheduler that sends mandatory course reminder emails:

- **Schedule:** Daily at 8:00 AM UTC
- **Trigger:** Sends reminders when 7 days or less remain before a course deadline
- **Deduplication:** The system tracks sent reminders to prevent duplicate emails

The scheduler starts automatically when the application runs.

## Project Structure

```
.
├── app/
│   ├── __init__.py          # Application factory
│   ├── config.py             # Configuration settings
│   ├── models.py             # Database models
│   ├── routes.py             # Route handlers
│   ├── templates/            # HTML templates
│   ├── static/               # CSS, JS, images
│   └── utils/                # Helper functions
├── instance/                  # SQLite database location (create this folder)
├── main.py                   # Application entry point
├── pyproject.toml            # Python dependencies
└── README.md                 # This file
```

## Troubleshooting

### Database Errors

If you encounter database errors, delete the SQLite database file and restart the application:

```bash
rm instance/lms.db
# Then restart the application
```

### NLTK Download Issues

If NLTK data fails to download automatically:

1. Check your internet connection
2. Try downloading manually (see Document Analysis section above)
3. Check if a firewall is blocking the download

### Port Already in Use

If port 5000 is already in use:

```bash
# Use a different port
flask run --host=0.0.0.0 --port=8000
```

### Session/Cookie Issues in Local Development

For local development without HTTPS, you may need to modify `app/config.py`:

```python
SESSION_COOKIE_SAMESITE = 'Lax'  # Change from 'None' to 'Lax'
SESSION_COOKIE_SECURE = False     # Change from True to False
```

## Email Configuration (Optional)

To enable email features (password reset, reminders), you'll need to configure SMTP settings. Add these to your environment:

```bash
export MAIL_SERVER=smtp.gmail.com
export MAIL_PORT=587
export MAIL_USE_TLS=true
export MAIL_USERNAME=your-email@gmail.com
export MAIL_PASSWORD=your-app-password
```

**Note:** For Gmail, use an App Password, not your regular password.
