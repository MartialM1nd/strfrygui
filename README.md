# ⚠️ USE AT YOUR OWN RISK - VIBE CODED ⚠️

This project is vibe coded. It works, but may have bugs, security issues, or unexpected behavior. Review the code before running in production.

---

# StrfryGUI

A web-based management portal for [strfry](https://github.com/hoytech/strfry), a Nostr relay written in C++.

## Features

- **Real-time Metrics Dashboard** - View Prometheus metrics including events by kind, client/relay message counts
- **Event Management** - Search, view, and delete events using Nostr filters (NIP-01)
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

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/MartialM1nd/strfrygui.git
   cd strfrygui
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your strfry paths
   ```

4. **Get SSL certificate:**
   ```bash
   sudo certbot certonly --standalone -d strfrygui.your-domain.com
   ```

5. **Configure nginx:**
   ```bash
   sudo cp nginx.conf /etc/nginx/sites-available/strfrygui
   sudo ln -s /etc/nginx/sites-available/strfrygui /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   ```

6. **Install systemd service:**
   ```bash
   sudo cp strfrygui.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl start strfrygui
   ```

7. **First-time setup:**
   - Visit `https://strfrygui.your-domain.com`
   - Register the first admin user at `/register`
   - Create additional users as needed

## Configuration

Edit the `.env` file with your settings:

```env
SECRET_KEY=your-random-secret-key
STRFRY_BINARY=/usr/local/bin/strfry
STRFRY_CONFIG=/etc/strfry.conf
STRFRY_DB_PATH=/var/lib/strfry
STRFRY_METRICS_URL=http://localhost:7777/metrics
```

## User Roles

| Role | Permissions |
|------|-------------|
| **admin** | Full access: users, config, delete events, import/export, db ops |
| **moderator** | View metrics, search events, delete events |
| **viewer** | Read-only: metrics, event search, view config |

## Development

Run in development mode:
```bash
flask run --debug
```

## License

GPL-3.0 - See LICENSE file

## Acknowledgments

- [strfry](https://github.com/hoytech/strfry) by Doug Hoyte
- [nostr](https://github.com/nostr-protocol/nostr) protocol
