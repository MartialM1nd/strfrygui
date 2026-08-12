# AGENTS.md - StrfryGUI Developer Guide

StrfryGUI is a Flask-based web management portal for the strfry Nostr relay.

## Project Structure
```
strfrygui/
├── app.py           # Main Flask app, routes, forms
├── config.py        # Config classes (Config, Security)
├── models.py        # SQLAlchemy models
├── requirements.txt # Python dependencies
├── .env.example     # Environment template (copy to .env, never commit)
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
pytest tests/test_file.py   # single file
pytest tests/test_file.py::test_function  # single test function
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

## Flask Patterns

### Route with auth:
```python
@app.route('/endpoint', methods=['GET', 'POST'])
@admin_required  # Auth decorators before route
def handler_name():
    form = SomeForm()
    if form.validate_on_submit():
        return redirect(url_for('other_route'))
    return render_template('template.html', form=form)
```

### Form (Flask-WTF):
```python
class MyForm(FlaskForm):
    field_name = StringField('Label', validators=[DataRequired()])
    another_field = IntegerField('Label', validators=[Optional()])
```

### Database model:
```python
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
```

### API Endpoint:
```python
@app.route('/api/endpoint')
@viewer_or_higher  # or appropriate auth decorator
def api_endpoint():
    data = fetch_data()
    return jsonify({'data': data, 'has_more': bool})
```

## Database Migrations

This project uses simple ALTER TABLE migrations, not Flask-Migrate:

```python
def init_db():
    with app.app_context():
        db.create_all()
        from sqlalchemy import text
        with db.engine.connect() as conn:
            # Check if column exists
            result = conn.execute(text(
                "SELECT name FROM pragma_table_info('users') WHERE name='column_name'"
            ))
            if not result.fetchone():
                conn.execute(text("ALTER TABLE users ADD COLUMN column_name BOOLEAN DEFAULT 1"))
                conn.commit()
        
        # Ensure new tables exist
        from models import NewModel
        db.create_all()
```

## Security Requirements

- **Authentication**: NIP-07 extensions sign short-lived NIP-98 events with one-time server challenges
- **Operator identity**: Store canonical lowercase 64-character hex pubkeys; roles remain server-controlled
- **Auth decorators**: `@admin_required`, `@moderator_required`, `@viewer_or_higher`
- **CSRF**: Flask-WTF handles automatically - use `form.csrf_token.current_token` for AJAX
- **Rate limiting**: Flask-Limiter on `/login` and globally
- **Secrets**: Never log registration tokens, challenges, or signed auth events; use `.env` (never commit)

## HTML Templates

- Extend `base.html` for all pages
- **CRITICAL**: Always close `{% block content %}` with `{% endblock %}` before starting `{% block scripts %}`
- Use Bootstrap 5 with `data-bs-theme="dark"` for dark mode support
- Use theme-aware classes: `bg-body-secondary` (not `bg-light`)
- Access routes via `url_for('route_name')`

### Dark Mode
Bootstrap 5.3 uses `data-bs-theme="dark"` on `<html>`. Use theme-aware classes:
- ✅ `bg-body`, `bg-body-secondary`, `bg-body-tertiary`
- ❌ `bg-light`, `bg-dark` (won't adapt)

## JavaScript Patterns

### Fetch with CSRF Token
```javascript
function doAction() {
    const form = document.getElementById('actionForm');
    const csrfToken = form.querySelector('input[name="csrf_token"]').value;
    
    fetch('/api/endpoint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'csrf_token=' + encodeURIComponent(csrfToken) + '&param=value'
    }).then(r => r.json()).then(data => { /* handle */ });
}
```

### Infinite Scroll (IntersectionObserver)
```javascript
let currentOffset = 0;
let hasMore = true;
let isLoading = false;

const observer = new IntersectionObserver(function(entries) {
    if (entries[0].isIntersecting && hasMore && !isLoading) {
        loadMore();
    }
}, { rootMargin: '100px' });

const sentinel = document.getElementById('scrollSentinel');
if (sentinel) observer.observe(sentinel);

function loadMore() {
    isLoading = true;
    fetch('/api/endpoint?offset=' + currentOffset)
        .then(r => r.json())
        .then(data => {
            appendData(data.items);
            hasMore = data.has_more;
            currentOffset += data.items.length;
            isLoading = false;
        });
}
```

### Defensive DOM Access
```javascript
function loadData() {
    const element = document.getElementById('elementId');
    if (!element) {
        console.error('Element not found in DOM');
        return;
    }
    // ... rest of function
}
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
