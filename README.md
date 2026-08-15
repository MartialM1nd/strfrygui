# StrfryGUI

StrfryGUI is a Flask-based operations and moderation console for a local
[strfry](https://github.com/hoytech/strfry) Nostr relay. It combines relay
telemetry, event operations, moderation workflows, write-policy controls,
configuration editing, and administrative tooling in one role-aware web UI.

StrfryGUI manages live relay data and includes destructive operations. Deploy it
behind HTTPS, restrict access to trusted operators, use least-privilege service
accounts, and maintain backups of both the control-plane SQLite database and
the strfry event database.

## Current Capabilities

### Relay Operations

- Persistent dashboard summaries for relay health, event traffic, storage,
  write-policy outcomes, moderation workload, and operator attention states.
- Sampled connection, NIP-42 authentication, protocol-message, and slow-client
  telemetry. The UI reports aggregate activity rather than individual sessions.
- Event search by keyword, NIP-05 address, pubkey/npub, event ID, kind, time
  range, tag, or advanced Nostr JSON filter.
- Safe event inspection with escaped content and explicit sensitive-content
  reveal for NIP-36/content-warning-tagged events.
- Bounded JSONL import and export previews, including optional fried output and
  explicit confirmation before skipping signature verification.
- Negentropy tree management, compression dictionary inspection, and database
  compaction guarded by relay-process and cross-process maintenance checks.

### Moderation and Policy

- NIP-56 report queue with filtering, bounded pagination, review actions, event
  deletion, author bans, and durable purge tracking.
- Direct pubkey bans and exact-host NIP-05 domain bans with source provenance.
  A pubkey can remain banned through another direct or domain source after one
  source is removed.
- Bounded NIP-05 reconciliation using public-address-only HTTP and WebSocket
  connections, pinned DNS results, and signed kind-0 event validation.
- Domain operation details with verified and unresolved identities, search,
  independent pagination, and CSV export.
- Bundled strfry write-policy plugin with atomically published blocklist and
  trust-policy artifacts.
- Web-of-Trust and NIP-13 Proof-of-Work policy modes: Off, Monitor, and Enforce.
- Live policy-decision console with safe responsive rendering, local filters,
  pause/resume, rotation recovery, bounded browser retention, and bounded
  polling.

### Administration and Security

- Viewer, moderator, and administrator roles.
- Focused administration pages for operators, audit history, metadata relays,
  and the ban registry.
- Operator safeguards that prevent self-demotion, self-deactivation,
  self-deletion, and removal of the final active administrator.
- Audit history for authentication and significant configuration, data,
  moderation, policy, relay, and account mutations.
- Public-only metadata relay management with canonical URL handling, bounded
  WebSocket exchanges, signed metadata-event validation, and SSRF protections.
- Revision-protected, source-preserving, locked, and atomic editing of supported
  `strfry.conf` fields. Unsafe or unsupported files become read-only rather than
  falling back to direct writes.
- Global CSRF protection, secure session cookies, NIP-07/NIP-98 authentication,
  one-time replay-resistant challenges, and validated local login return URLs.
- Dark and light themes with responsive desktop and mobile layouts.

## Access Model

| Capability | Viewer | Moderator | Admin |
| --- | :---: | :---: | :---: |
| Dashboard, metrics, and connection summaries | Yes | Yes | Yes |
| Search and inspect events | Yes | Yes | Yes |
| Delete events or delete by filter | No | Yes | Yes |
| Policy decision log | No | Yes | Yes |
| Moderation reports and event purges | No | Yes | Yes |
| Ban pubkeys and reconcile NIP-05 domains | No | Yes | Yes |
| View domain details and export domain CSV | No | Yes | Yes |
| Retry pending purge or enforcement publication | No | Yes | Yes |
| Unban pubkeys or domains | No | No | Yes |
| Import/export and database maintenance | No | No | Yes |
| Relay and plugin configuration | No | No | Yes |
| Operators, audit history, metadata relays, and ban registry | No | No | Yes |
| Rotate own Nostr key | Yes | Yes | Yes |
| Assign another operator's Nostr key | No | No | Yes |

## Architecture

- **Application:** Flask 3, Flask-Login, Flask-WTF, and Flask-Limiter.
- **Control-plane database:** SQLite via SQLAlchemy. It stores accounts, audit
  history, moderation state, ban provenance, telemetry samples, purge tracking,
  metadata relays, and WoT settings.
- **Relay database:** The separate strfry database configured by
  `STRFRY_DB_PATH`.
- **Relay integration:** Local strfry CLI commands using argument arrays without
  a shell.
- **Telemetry:** Prometheus metrics exposed by strfry and sampled by StrfryGUI.
- **External verification:** Bounded HTTPS and WebSocket requests for NIP-05 and
  public metadata relays.
- **Frontend:** Server-rendered Jinja templates, Bootstrap 5, Bootstrap Icons,
  Chart.js, and small framework-free JavaScript controllers.
- **Background work:** In-process workers for moderation reconciliation,
  reporting, dashboard sampling, and WoT builds.

## Requirements

- Linux.
- Python 3.11 or newer.
- A working local strfry installation and configuration.
- Permission for the StrfryGUI service account to execute the strfry binary and
  access the relay database for the operations you enable.
- A strfry Prometheus endpoint for dashboard and connection telemetry.
- Public HTTPS and WebSocket egress for NIP-05 and metadata lookups.
- HTTPS termination for browser access. Session cookies are always marked
  `Secure`.

nginx and Let's Encrypt are useful deployment choices but are not application
runtime dependencies.

## Installation

The included paths and service files assume installation under
`/opt/strfrygui`, a web service account named `www-data`, and a relay service
account named `nostr`. Adjust them for your system.

### 1. Install the Application

Keep application source root-owned. The web process should not be able to modify
Python source, templates, or the write-policy plugin.

```bash
sudo git clone https://github.com/awstephan/strfrygui.git /opt/strfrygui
sudo python3 -m venv /opt/strfrygui/venv
sudo /opt/strfrygui/venv/bin/pip install -r /opt/strfrygui/requirements.txt
sudo chown -R root:root /opt/strfrygui
```

### 2. Create State Directories

The SQLite database should live outside the source tree. The runtime directory
is shared with the bundled write-policy plugin.

```bash
sudo groupadd -f -r strfry-observers
sudo usermod -aG strfry-observers nostr
sudo usermod -aG strfry-observers www-data
sudo install -d -o www-data -g www-data -m 0750 /var/lib/strfrygui
sudo install -d -o root -g strfry-observers -m 2770 /opt/strfrygui/runtime
```

Restart services after changing group membership.

### 3. Configure the Environment

```bash
sudo cp /opt/strfrygui/.env.example /opt/strfrygui/.env
sudo chown root:www-data /opt/strfrygui/.env
sudo chmod 0640 /opt/strfrygui/.env
sudo editor /opt/strfrygui/.env
```

Startup rejects symlinked dotenv files, files accessible by other users, and
files writable by the service group. Both secrets must contain at least 32
characters when configured.

At minimum, set unique non-empty values for `SECRET_KEY` and
`REGISTRATION_TOKEN`, and use the dedicated state path:

```env
SECRET_KEY=<generated-secret>
REGISTRATION_TOKEN=<generated-secret>
DATABASE_URL=sqlite:////var/lib/strfrygui/strfrygui.db
STRFRY_BINARY=/usr/local/bin/strfry
STRFRY_CONFIG=/etc/strfry.conf
STRFRY_DB_PATH=/var/lib/strfry
STRFRY_METRICS_URL=http://localhost:7777/metrics
TRUSTED_PROXY_COUNT=1
```

Generate secrets with:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

`TRUSTED_PROXY_COUNT=1` is appropriate when exactly one trusted reverse proxy
sits between clients and Flask. Use `0` when Flask is directly exposed.

### 4. Configure HTTPS

Update `nginx.conf` with the real hostname and certificate paths. Obtain a valid
certificate before enabling the final TLS configuration, or use your ACME
client's nginx/webroot integration.

The application permits imports up to 5 MiB by default. Configure nginx with a
slightly larger request allowance, for example:

```nginx
client_max_body_size 6m;
```

Align reverse-proxy timeouts with the bounded import, export, and maintenance
operations you intend to use.

### 5. Start the Service

`strfrygui.service` is a simple single-process reference unit:

```bash
sudo cp /opt/strfrygui/strfrygui.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now strfrygui
```

The bundled unit uses Flask's server. Review and harden it for your deployment.
Do not switch blindly to multiple WSGI workers: this project currently has
in-process queues, workers, schedulers, and status state that would be duplicated
across processes.

### 6. Configure the First Nostr Administrator

Install or unlock a NIP-07 browser extension, then visit `/register` and enter
the configured registration token. On an existing installation, setup requires
exactly one active administrator without a Nostr pubkey; it binds the signing
pubkey to that account and preserves its audit history. On a fresh installation,
setup creates the first administrator. The role is always admin.

Set `PUBLIC_BASE_URL` to the exact externally visible HTTPS origin before
setup. NIP-98 signatures bind login to this URL, so it must match the URL used
in the browser. Administrators provision all other operator pubkeys from the
Operators page; unknown pubkeys are denied. Operator names come from the latest
signed kind-0 profile `name` and refresh at login. A unique shortened npub is
used when the profile has no usable unique name.

## Configuration Reference

### Core Settings

| Variable | Purpose | Default |
| --- | --- | --- |
| `SECRET_KEY` | Flask session and CSRF signing secret; required | None |
| `REGISTRATION_TOKEN` | Token for initial Nostr administrator setup | None |
| `PUBLIC_BASE_URL` | Exact externally visible HTTPS origin used in NIP-98 signatures | `https://localhost` |
| `NOSTR_AUTH_CHALLENGE_TTL` | One-time challenge lifetime in seconds; minimum 10 | `60` |
| `NOSTR_AUTH_TIMESTAMP_TOLERANCE` | Accepted event clock skew in seconds; minimum 10 | `60` |
| `DATABASE_URL` | Control-plane SQLite URL | `sqlite:///strfrygui.db` |
| `STRFRY_BINARY` | strfry executable | `/usr/local/bin/strfry` |
| `STRFRY_CONFIG` | strfry configuration file | `/etc/strfry.conf` |
| `STRFRY_DB_PATH` | strfry event database directory | `/var/lib/strfry` |
| `STRFRY_METRICS_URL` | Prometheus metrics endpoint | `http://localhost:7777/metrics` |
| `DASHBOARD_SAMPLE_INTERVAL` | Telemetry sample interval; minimum 60 seconds | `60` |
| `TRUSTED_PROXY_COUNT` | Trusted proxy count for audit client addresses | `0` |

### Data Operation Limits

| Variable | Purpose | Default |
| --- | --- | --- |
| `IMPORT_MAX_BYTES` | Maximum pasted JSONL import size | `5242880` |
| `IMPORT_MAX_EVENTS` | Maximum events in one import | `10000` |
| `EXPORT_MAX_BYTES` | Maximum captured export output | `5242880` |

### Moderation and Network Limits

The `.env.example` file documents report synchronization, domain scan, NIP-05,
response-size, address-count, and WebSocket message limits. Defaults are bounded
in `config.py`; review them before increasing any value.

Metadata relays are seeded into SQLite on first startup and managed under
**Admin > Metadata relays**. New connections are limited to `ws://` and
`wss://` destinations whose DNS answers are all globally routable. Private,
loopback, link-local, multicast, and mixed public/private destinations are
rejected.

## Safe strfry Configuration Editing

The Configuration and Plugins pages edit only these supported fields:

- `relay.info.name`
- `relay.info.description`
- `relay.info.pubkey`
- `relay.info.contact`
- `relay.bind`
- `relay.port`
- `relay.writePolicy.plugin`
- `relay.writePolicy.timeoutSeconds`
- `relay.writePolicy.lookbackSeconds`

StrfryGUI preserves the supported source structure, checks a SHA-256 revision,
locks concurrent changes, writes and syncs a temporary file, and atomically
replaces the target. Malformed, ambiguous, unsupported, or non-atomically
writable configurations are shown read-only.

Do not grant `www-data` write access to all of `/etc`. To enable web-based
editing, place the relay configuration in a dedicated directory shared only by
strfry and StrfryGUI:

```bash
sudo groupadd -f -r strfry-config
sudo usermod -aG strfry-config nostr
sudo usermod -aG strfry-config www-data
sudo install -d -o root -g strfry-config -m 2770 /etc/strfrygui
sudo install -o root -g strfry-config -m 0660 /etc/strfry.conf /etc/strfrygui/strfry.conf
```

Point both services at `/etc/strfrygui/strfry.conf` and restart them. Avoid
manual edits while saving through the GUI. Symlink targets are retained; hard
links are not recommended because atomic replacement changes file identity.

## Write-Policy Plugin

Add or update the `writePolicy` section in `strfry.conf`:

```text
relay {
    writePolicy {
        plugin = "/opt/strfrygui/utils/blocklist_plugin.py"
        timeoutSeconds = 10
        lookbackSeconds = 0
    }
}
```

Make the bundled plugin executable and restart strfry after changing its path:

```bash
sudo chmod 0755 /opt/strfrygui/utils/blocklist_plugin.py
sudo systemctl restart strfry
```

Once the plugin is configured and running, successful blocklist and trust-policy
publication is picked up without restarting strfry. Publication failures remain
visible and retryable. A published artifact proves that the file was written;
it does not by itself prove that the running relay loaded the plugin.

Ban operations have separate observable stages:

1. The ban and its provenance are committed to SQLite.
2. The complete blocklist is atomically published to
   `/opt/strfrygui/runtime/blocklist.json`.
3. The running plugin reloads the artifact.
4. Existing matching events are purged through durable, retryable work.

Direct and domain ban sources overlap. Removing one source does not allow the
pubkey if another source remains active. Purged events cannot be restored.

### Web of Trust and Proof of Work

- **Off:** Direct/domain bans remain active; trust and PoW do not reject other
  authors.
- **Monitor:** Decisions and counters are recorded without rejecting low-trust
  events.
- **Enforce:** Authors below the trust threshold must satisfy the configured
  NIP-13 PoW and rate policy.

The graph is built from signed kind-3 follow lists already stored locally. It is
bounded to two hops, 5,000 direct identities, 100,000 total identities, 500,000
edges, and 2,000 follows per contributing list. Failed builds retain the last
valid snapshot; stale snapshots trust only configured roots until a successful
rebuild.

Local imports, synchronization, and stored-event replay bypass trust and PoW
checks. Explicit bans always take precedence.

### Policy Decision Log

The plugin records decision metadata after responding to strfry. It does not log
event content, tags, signatures, or raw requests. The log rotates at 5 MiB with
one 5 MiB backup. The browser retains at most 1,000 decisions and polls every
2.5 seconds while visible and unpaused.

## Database Maintenance

Database compaction acts directly on strfry storage. StrfryGUI requires explicit
confirmation, refuses to start while visible strfry processes are running, and
also refuses when process visibility is unavailable. Stop the relay and verify
backups before compacting.

Import, event deletion, negentropy mutation, and compaction share a filesystem
maintenance lock to prevent overlapping GUI writes across worker processes.

## Backup and Recovery

Back up these locations before upgrades or destructive maintenance:

- The control-plane SQLite database from `DATABASE_URL`.
- The strfry event database at `STRFRY_DB_PATH`.
- `strfry.conf`.
- `/opt/strfrygui/runtime`, including policy artifacts and decision logs.

Do not delete the SQLite database merely to reset an account. It also contains
audit history, reports, bans and provenance, purge status, metadata relays,
telemetry samples, and WoT state.

## Development

Use isolated development paths. Importing `app.py` initializes the database,
publishes policy state, and starts background workers and schedulers.

```bash
python3.11 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install pytest ruff
```

Run the test suite:

```bash
SECRET_KEY=test-secret python -m pytest
```

Run focused tests:

```bash
SECRET_KEY=test-secret python -m pytest tests/test_moderation.py
SECRET_KEY=test-secret python -m pytest tests/test_admin.py::test_admin_is_get_only_redirect_to_operators
```

Lint:

```bash
ruff check .
```

For local execution, use an isolated `.env`, SQLite database, runtime directory,
strfry configuration, and relay database. `--no-reload` avoids duplicate
background workers from the debug reloader:

```bash
python -m flask --app app run --debug --no-reload
```

Authenticated browser sessions require HTTPS because session cookies are always
marked `Secure`. Authentication challenge and verification endpoints use the
configured `RATELIMIT_LOGIN` limit (`5 per minute` by default). Nostr key
rotation first requires a signature from the currently assigned key, then a
signature from the new key; successful rotation revokes all existing sessions.

## Troubleshooting

### Service startup

```bash
sudo systemctl status strfrygui
sudo journalctl -u strfrygui -n 100
```

Check that:

- `SECRET_KEY` is set and `.env` is readable by the service account.
- The SQLite directory is writable by `www-data`.
- The runtime directory is writable by both StrfryGUI and the plugin group.
- The strfry binary is executable by `www-data`.
- The configured relay database permissions match the operations being used.
- `STRFRY_METRICS_URL` is reachable for telemetry.
- `strfry.conf` and its containing directory have the permissions required for
  atomic replacement if web editing is enabled.

### Read-only configuration

The UI intentionally becomes read-only when parsing, revision, locking,
ownership, group, or atomic replacement requirements cannot be met. Review the
diagnostic shown on the page and the application log; do not work around it by
granting broad write access to system directories.

### Missing policy enforcement

Confirm all of the following:

- The bundled plugin is selected and is a root-owned, non-writable executable.
- strfry was restarted after a plugin path change.
- The Plugins page reports successful policy publication.
- The shared runtime directory is accessible to both services.
- Recent policy telemetry or decision-log activity is present.

The plugin rejects network writes until it has loaded both a valid blocklist and
a valid trust-policy artifact. Explicit empty blocklists and `off` policies are
valid; missing or malformed initial artifacts are not. Domain reconciliation
limits unique profile candidates and leaves destructive event deletion to the
bounded durable purge worker.

## Project Layout

```text
app.py                 Flask routes, forms, workers, and startup
config.py              Environment-backed application configuration
models.py              SQLite control-plane models and indexes
utils/configuration.py Safe source-preserving strfry config editor
utils/relay.py         Public-only metadata relay networking
utils/moderation.py    Ban, publication, purge, and unban workflows
utils/wot.py           WoT graph and trust-policy publication
utils/strfry.py        strfry CLI integration
templates/             Server-rendered operations UI
static/                Shared CSS and JavaScript controllers
tests/                 Pytest regression suite
```

## License

GPL-3.0. See [LICENSE](LICENSE).

## Acknowledgments

- [strfry](https://github.com/hoytech/strfry) by Doug Hoyte
- [Nostr protocol](https://github.com/nostr-protocol/nostr)
