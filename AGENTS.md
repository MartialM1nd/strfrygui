# AGENTS.md - StrfryGUI Developer Guide

StrfryGUI is a Flask-based web management portal for the strfry Nostr relay.

## Project Structure
```
strfrygui/
├── app.py           # Main Flask app, routes, forms
├── config.py        # Config classes (Config, Security)
├── models.py        # SQLAlchemy models (User, AuditLog)
├── requirements.txt # Python dependencies
├── .env.example     # Environment template (copy to .env, never commit .env)
├── utils/           # strfry.py, metrics.py, auth.py
├── templates/       # Jinja2 HTML templates
└── static/          # CSS, JS
```

## Build/Test Commands

```bash
# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Run development
flask run --debug

# Run tests
pytest                      # all tests
pytest tests/test_file.py::test_function  # single test
pytest --cov=app --cov-report=html        # with coverage

# Lint (install first: pip install ruff black)
ruff check .
black .
```

## Code Style

### Imports (order matters)
```python
# Standard library
import os
from datetime import datetime

# Third-party
from flask import Flask, render_template
from flask_login import login_required, current_user

# Local application
from config import Config
from models import db, User
from utils.strfry import scan_events
```

### Naming
- Variables/functions: `snake_case` (e.g., `scan_events`, `user_count`)
- Classes: `PascalCase` (e.g., `LoginForm`, `User`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `MAX_CONNECTIONS`)
- Files: `snake_case` (e.g., `strfry.py`)

### Type Hints & Docstrings
- Use type hints where beneficial but not required
- Add docstrings for complex functions

```python
def scan_events(filter_json: dict, limit: int = 100) -> list[dict]:
    """Scan strfry database for events matching the filter."""
    # ...
```

### Error Handling
- Use custom exceptions for domain errors
- Catch specific exceptions, not bare `Exception`

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

### Key Flask Patterns

**Route with auth:**
```python
@app.route('/endpoint', methods=['GET', 'POST'])
@admin_required  # Auth decorators before route
def handler_name():
    form = SomeForm()
    if form.validate_on_submit():
        return redirect(url_for('other_route'))
    return render_template('template.html', form=form)
```

**Form (Flask-WTF):**
```python
class MyForm(FlaskForm):
    field_name = StringField('Label', validators=[DataRequired()])
    another_field = IntegerField('Label', validators=[Optional()])
```

**Database model:**
```python
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
```

## Database Migrations

This project uses simple ALTER TABLE migrations, not Flask-Migrate:

```python
def init_db():
    with app.app_context():
        db.create_all()
        from sqlalchemy import text
        with db.engine.connect() as conn:
            # Add missing columns for upgrades
            result = conn.execute(text(
                "SELECT name FROM pragma_table_info('users') WHERE name='column_name'"
            ))
            if not result.fetchone():
                conn.execute(text("ALTER TABLE users ADD COLUMN column_name BOOLEAN DEFAULT 1"))
                conn.commit()
```

## Security Requirements

- **Passwords**: 21+ chars, uppercase, lowercase, digit, special char (except admin-created users: 8+ chars)
- **must_change_password**: Admin-created users must change password on first login
- **Auth decorators**: `@admin_required`, `@moderator_required`, `@viewer_or_higher`
- CSRF: Flask-WTF handles automatically
- Rate limiting: Flask-Limiter on `/login` and globally
- Secrets: Never log passwords; use `.env` (never commit)

## HTML Templates

- Extend `base.html` for all pages
- Use Bootstrap 5 with `data-bs-theme="dark"` for dark mode support
- Use theme-aware classes: `bg-body-secondary` (not `bg-light`)
- Block structure: `{% block content %}{% endblock %}` and `{% block scripts %}{% endblock %}`
- Access routes via `url_for('route_name')`

## Dark Mode

Bootstrap 5.3 uses `data-bs-theme="dark"` on `<html>`. Use theme-aware classes:
- ✅ `bg-body`, `bg-body-secondary`, `bg-body-tertiary`
- ❌ `bg-light`, `bg-dark` (won't adapt)

## JavaScript (Dashboard)

Chart.js for real-time charts with 5-second auto-refresh:
```javascript
const chart = new Chart(document.getElementById('chartId'), {
    type: 'line',
    data: { labels: [], datasets: [...] },
    options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
});

setInterval(async () => {
    const data = await fetch('/api/endpoint').then(r => r.json());
    // update chart and call chart.update('none')
}, 5000);
```

## Configuration

Required `.env` variables:
```bash
SECRET_KEY=<generate: python3 -c "import secrets; print(secrets.token_hex(32))">
REGISTRATION_TOKEN=<generate same way>
DATABASE_URL=sqlite:////opt/strfrygui/strfrygui.db
STRFRY_BINARY=/usr/local/bin/strfry
STRFRY_CONFIG=/etc/strfry.conf
STRFRY_DB_PATH=/var/lib/strfry
STRFRY_METRICS_URL=http://localhost:7777/metrics
```

## Important Notes

- The `.env` file should NEVER be committed (already in `.gitignore`)
- Copy `.env.example` to `.env` and fill in values
- Database is SQLite; stored at `DATABASE_URL` path
- All strfry CLI calls use `subprocess.run()` with list args (never `shell=True`)