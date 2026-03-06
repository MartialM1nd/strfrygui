# AGENTS.md - StrfryGUI Developer Guide

This file provides guidelines for AI agents working on the StrfryGUI project.

## Project Overview

StrfryGUI is a Flask-based web management portal for the strfry Nostr relay. It provides a dashboard for monitoring relay metrics, managing events, importing/exporting data, and administering users.

## Project Structure

```
strfrygui/
├── app.py              # Main Flask application with routes and forms
├── config.py           # Configuration classes (Config, Security)
├── models.py           # SQLAlchemy models (User, AuditLog)
├── requirements.txt    # Python dependencies
├── .env.example        # Environment variables template
├── nginx.conf          # Nginx configuration template
├── strfrygui.service  # Systemd service file
├── utils/
│   ├── __init__.py
│   ├── strfry.py      # strfry CLI wrapper
│   ├── metrics.py      # Prometheus metrics parser
│   └── auth.py        # Auth decorators
├── templates/          # Jinja2 HTML templates
└── static/
    └── style.css
```

## Build/Lint/Test Commands

### Installation
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Application
```bash
# Development mode
flask run --debug

# Production mode (via systemd)
sudo systemctl start strfrygui

# Or manually with Gunicorn
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

### Running Tests
Currently no test framework is configured. To add tests:
```bash
# Install test dependencies
pip install pytest pytest-flask

# Run all tests
pytest

# Run a single test file
pytest tests/test_models.py

# Run a single test function
pytest tests/test_models.py::test_user_password
```

### Linting
No linter is currently configured. Recommended setup:
```bash
# Install linting tools
pip install ruff black isort

# Run ruff (fast linter)
ruff check .

# Run black (formatter)
black .

# Sort imports
isort .
```

## Code Style Guidelines

### Imports
- Standard library imports first
- Third-party imports second
- Local application imports last
- Use explicit relative imports within the application

Example:
```python
# Standard library
import os
import json
from datetime import datetime

# Third-party
from flask import Flask, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length

# Local application
from config import Config, Security
from models import db, User, AuditLog
from utils.strfry import scan_events, delete_events
from utils.metrics import get_summary
```

### Naming Conventions
- **Variables/functions**: snake_case (e.g., `scan_events`, `user_count`)
- **Classes**: PascalCase (e.g., `LoginForm`, `User`, `StrfryError`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `MAX_CONNECTIONS`, `DEFAULT_LIMIT`)
- **Files**: snake_case (e.g., `strfry.py`, `metrics.py`)

### Functions and Classes
- Keep functions small and focused (single responsibility)
- Use type hints where beneficial but not required
- Add docstrings for complex functions
- Use decorators for cross-cutting concerns (auth, rate limiting)

Example:
```python
def scan_events(filter_json, limit=100):
    """
    Scan strfry database for events matching the given filter.
    
    Args:
        filter_json: Nostr filter as dict
        limit: Maximum number of events to return
        
    Returns:
        List of event dictionaries
        
    Raises:
        StrfryError: If strfry command fails
    """
    # Implementation
```

### Error Handling
- Use custom exception classes for domain-specific errors
- Catch specific exceptions, not bare `Exception`
- Return meaningful error messages to users via flash() or render_template

Example:
```python
class StrfryError(Exception):
    """Raised when strfry CLI command fails."""
    pass


def scan_events(filter_json, limit=100):
    try:
        result = subprocess.run(cmd, ...)
        if result.returncode != 0:
            raise StrfryError(result.stderr)
    except subprocess.TimeoutExpired:
        raise StrfryError("Command timed out")
```

### Flask Patterns

#### Routes
```python
@app.route('/endpoint', methods=['GET', 'POST'])
@decorator_required  # Auth decorators go before route
def handler_name():
    form = SomeForm()
    if form.validate_on_submit():
        # Process form
        return redirect(url_for('other_route'))
    return render_template('template.html', form=form)
```

#### Forms (Flask-WTF)
```python
class MyForm(FlaskForm):
    field_name = StringField('Label', validators=[DataRequired()])
    another_field = IntegerField('Label', validators=[Optional()])
```

#### Database Models
```python
class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    
    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(...)
```

#### Template Context
- Add global template variables via `@app.context_processor`
- Add template filters via `@app.template_filter('name')`

```python
@app.context_processor
def inject_user():
    return dict(User=User)

@app.template_filter('datetime')
def datetime_filter(ts):
    from datetime import datetime
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
```

### Security Considerations
- Never log passwords or secrets
- Use parameterized queries (SQLAlchemy handles this)
- Validate all user input
- Use CSRF protection (Flask-WTF provides this)
- Hash passwords with bcrypt (already in use)
- Rate limit sensitive endpoints
- Require HTTPS in production (SESSION_COOKIE_SECURE = True)

### HTML Templates
- Extend `base.html` for all pages
- Use Bootstrap 5 classes for styling
- Use Jinja2 block system for content
- Access route names via `url_for()`
- Use `{% with %}` for local variables

## Configuration

### Environment Variables (.env)
```bash
SECRET_KEY=your-random-secret-key
DATABASE_URL=sqlite:////opt/strfrygui/strfrygui.db
STRFRY_BINARY=/usr/local/bin/strfry
STRFRY_CONFIG=/etc/strfry.conf
STRFRY_DB_PATH=/var/lib/strfry
STRFRY_METRICS_URL=http://localhost:7777/metrics
```

### strfry Configuration
The application expects strfry to be installed and configured at paths specified in .env. The default paths point to common installation locations.

## Common Tasks

### Adding a New Route
1. Add route in app.py with appropriate decorator
2. Create form class if needed
3. Create template in templates/
4. Add navigation link in base.html

### Adding a New Model
1. Define class in models.py
2. Import and use db.Model base class
3. Add relationship if needed
4. Database auto-creates on app startup

### Adding a Template Filter
1. Add function in app.py
2. Decorate with `@app.template_filter('name')`
3. Use in template as `{{ value|name }}`

### Modifying strfry CLI Calls
1. Edit utils/strfry.py
2. Add function with validated arguments
3. Use subprocess.run() with list of args (not shell=True)
4. Handle errors and return meaningful data

## Testing Guidelines

When adding tests:
- Use pytest fixtures for common setup
- Test happy path and error cases
- Mock external dependencies (strfry CLI, HTTP requests)
- Use client fixture for Flask testing

Example test:
```python
import pytest
from app import app
from models import db, User

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()

def test_login_page(client):
    response = client.get('/login')
    assert response.status_code == 200
```

## Deployment

The application is designed to run behind nginx with SSL termination. See:
- README.md for full deployment instructions
- nginx.conf for nginx configuration template
- strfrygui.service for systemd service

## Resources

- Flask: https://flask.palletsprojects.com/
- Flask-WTF: https://flask-wtf.readthedocs.io/
- Flask-Login: https://flask-login.readthedocs.io/
- SQLAlchemy: https://docs.sqlalchemy.org/
- strfry: https://github.com/hoytech/strfry
