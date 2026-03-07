# ⚠️ USE AT YOUR OWN RISK - VIBE CODED ⚠️

This project is vibe coded. It works, but may have bugs, security issues, or unexpected behavior. Review the code before running in production.

---

# StrfryGUI

A web-based management portal for [strfry](https://github.com/hoytech/strfry), a Nostr relay written in C++.

## Features

- **Real-time Metrics Dashboard** - Live line charts showing events, client messages, and relay message rates with 5-second auto-refresh
- **Event Management** - Combined search and delete UI with dropdown selectors for pubkey (supports npub), kind, time range, tag, or advanced filters
- **Dark Mode** - Toggle between light and dark themes, with automatic system preference detection
- **Data Import/Export** - Import and export events in JSONL format, with fried export support for faster re-imports
- **Negentropy Trees** - Create, build, and manage negentropy sync trees
- **Compression Dictionaries** - View compression dictionary statistics
- **Database Compaction** - Initiate database compaction to reclaim disk space
- **Configuration Editor** - Edit relay configuration (name, description, pubkey, contact, bind address, port)
- **Connection Monitoring** - View real-time connection and message statistics
- **Multi-user Authentication** - Role-based access control (admin, moderator, viewer)
- **Audit Logging** - Track user actions for security and debugging

## Tech Stack

- **Backend**: Python Flask
- **Database**: SQLite (for user accounts)
- **Auth**: Flask-Login with bcrypt password hashing
- **Frontend**: Bootstrap 5, Chart.js
- **Communication**: Local subprocess calls to strfry CLI + HTTP scraping of Prometheus metrics

## Security

- Role-based access control with three levels: `admin`, `moderator`, `viewer`
- bcrypt password hashing
- CSRF protection via Flask-WTF
- Rate limiting on login attempts
- All strfry commands use validated arguments (no shell injection)
- Audit logging for all admin actions
- Sessions configured with secure cookies (HTTPS required in production)

## Requirements

- Python 3.9+
- strfry relay installed and configured
- nginx (for reverse proxy with SSL)
- Let's Encrypt SSL certificate
- bech32>=1.2.0 (for npub support)

## Installation

The app installs to `/opt/strfrygui` and runs as the `www-data` user.

1. **Clone and install to /opt/:**
   ```bash
   sudo git clone https://github.com/MartialM1nd/strfrygui.git /opt/strfrygui
   cd /opt/strfrygui
   ```

2. **Create virtual environment:**
   ```bash
   sudo python3 -m venv venv
   sudo ./venv/bin/pip install -r requirements.txt
   ```

3. **Copy and edit configuration:**
   ```bash
   sudo cp .env.example .env
   sudo nano .env  # Edit SECRET_KEY at minimum
   ```

4. **Edit nginx.conf with your domain:**
   ```bash
   sudo nano nginx.conf  # Replace YOUR_DOMAIN.COM with your actual domain
   ```

5. **Configure nginx:**
   ```bash
   sudo cp nginx.conf /etc/nginx/sites-available/strfrygui
   sudo ln -s /etc/nginx/sites-available/strfrygui /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   ```

6. **Get SSL certificate:**
   ```bash
   sudo certbot certonly --standalone -d strfrygui.YOUR_DOMAIN.COM
   ```

7. **Set permissions:**
   ```bash
   sudo chown -R www-data:www-data /opt/strfrygui
   ```

8. **Install systemd service:**
   ```bash
   sudo cp strfrygui.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable strfrygui
   sudo systemctl start strfrygui
   ```

9. **First-time setup:**
   - Visit `https://strfrygui.YOUR_DOMAIN.COM`
   - Register the first admin user at `/register`
   - Create additional users as needed

## Configuration

Edit `/opt/strfrygui/.env` with your settings:

```env
# Required: Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=

# Required for first-time registration: Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
REGISTRATION_TOKEN=

DATABASE_URL=sqlite:////opt/strfrygui/strfrygui.db
STRFRY_BINARY=/usr/local/bin/strfry
STRFRY_CONFIG=/etc/strfry.conf
STRFRY_DB_PATH=/var/lib/strfry
STRFRY_METRICS_URL=http://localhost:7777/metrics
```

Generate secure tokens:
```bash
# For SECRET_KEY
python3 -c "import secrets; print(secrets.token_hex(32))"

# For REGISTRATION_TOKEN
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### First-Time Registration

The first user must register at `/register` with the correct `REGISTRATION_TOKEN` set in `.env`. This prevents unauthorized registration before you secure your relay. After the first user is created, registration is automatically closed.

## Files You Must Edit After Cloning

| File | What to change |
|------|----------------|
| `.env` | `SECRET_KEY` (required), `REGISTRATION_TOKEN` (required for first-time setup) |
| `nginx.conf` | `strfrygui.YOUR_DOMAIN.COM`, SSL certificate paths |

## User Roles

| Role | Permissions |
|------|-------------|
| **admin** | Full access: users, config, delete events, import/export, db ops |
| **moderator** | View metrics, search events, delete events |
| **viewer** | Read-only: metrics, event search, view config |

## Development

Run in development mode:
```bash
cd /opt/strfrygui
source venv/bin/activate
flask run --debug
```

## Troubleshooting

**Service won't start:**
```bash
sudo systemctl status strfrygui
sudo journalctl -u strfrygui -n 50
```

**Can't connect:**
- Check nginx is running: `sudo systemctl status nginx`
- Check firewall: `sudo ufw status`

**Database issues:**
- Delete `/opt/strfrygui/strfrygui.db` and restart to reset users

## License

GPL-3.0 - See LICENSE file

## Acknowledgments

- [strfry](https://github.com/hoytech/strfry) by Doug Hoyte
- [nostr](https://github.com/nostr-protocol/nostr) protocol
