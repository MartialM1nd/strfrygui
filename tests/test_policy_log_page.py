from pathlib import Path

from flask import Flask, jsonify, render_template
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'templates' / 'policy_log.html'
SCRIPT = ROOT / 'static' / 'policy_log.js'
STYLES = ROOT / 'static' / 'style.css'


def policy_log_test_app():
    app = Flask(
        __name__,
        template_folder=str(ROOT / 'templates'),
        static_folder=str(ROOT / 'static'),
    )
    app.config.update(SECRET_KEY='policy-log-test', TESTING=True)
    CSRFProtect(app)
    login_manager = LoginManager(app)

    @login_manager.user_loader
    def load_user(_user_id):
        return None

    @app.route('/')
    def index():
        return ''

    @app.route('/events')
    def events():
        return ''

    @app.route('/api/write-policy-events')
    def api_write_policy_events():
        return jsonify({})

    @app.route('/policy-log')
    def policy_log():
        return render_template('policy_log.html')

    return app


def test_policy_log_template_renders_operations_console_contract():
    response = policy_log_test_app().test_client().get('/policy-log')

    assert response.status_code == 200
    page = response.get_data(as_text=True)
    assert 'WRITE POLICY OPERATIONS' in page
    assert 'data-api-url="/api/write-policy-events"' in page
    assert 'data-events-url="/events"' in page
    assert 'src="/static/policy_log.js"' in page
    assert 'id="feedFreshness"' in page
    assert 'id="clearFiltersButton"' in page
    assert 'id="clearViewButton"' in page
    assert 'Advanced filters' in page
    assert 'id="decisionList"' in page
    assert 'id="policyState"' in page
    assert 'id="resetNotice"' in page
    assert '<table' not in page


def test_policy_log_javascript_is_external_and_uses_dom_safe_rendering():
    template = TEMPLATE.read_text()
    script = SCRIPT.read_text()

    assert template.count('<script') == 1
    assert '<script src="{{ url_for(\'static\', filename=\'policy_log.js\') }}" defer></script>' in template
    assert 'textContent' in script
    assert 'document.createElement' in script
    assert 'document.createDocumentFragment' in script
    for unsafe_sink in ('innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write'):
        assert unsafe_sink not in script


def test_policy_log_polling_is_single_bounded_abortable_and_visibility_aware():
    script = SCRIPT.read_text()

    assert script.count('fetch(') == 1
    assert 'new AbortController()' in script
    assert 'signal: controller.signal' in script
    assert 'REQUEST_TIMEOUT_MS = 8000' in script
    assert 'MAX_CATCHUP_POLLS = 4' in script
    assert 'MAX_RETRY_DELAY_MS = 30000' in script
    assert 'if (requestController || !pollingAllowed()) return;' in script
    assert "document.addEventListener('visibilitychange'" in script
    assert 'document.hidden' in script
    assert 'requestController.abort()' in script
    assert 'resumeAfterRequest' in script
    assert 'Math.min(retryDelay * 2, MAX_RETRY_DELAY_MS)' in script


def test_policy_log_validates_batch_and_event_types_before_rendering():
    script = SCRIPT.read_text()

    assert 'const data = validateBatch(await response.json());' in script
    assert 'Array.isArray(data.events)' in script
    assert 'data.events.length > MAX_BATCH_RECORDS' in script
    assert "typeof data.reset !== 'boolean'" in script
    assert "typeof data.has_more !== 'boolean'" in script
    assert "typeof data.available !== 'boolean'" in script
    assert 'Number.isSafeInteger(record.timestamp_ms)' in script
    assert 'new Date(record.timestamp_ms).getTime()' in script
    assert "record.action !== 'accept' && record.action !== 'reject'" in script
    assert "assertNullableString(record.event_id, 'event_id', 128)" in script
    assert "assertNullableString(record.pubkey, 'pubkey', 128)" in script


def test_policy_log_cards_and_states_have_responsive_styles():
    styles = STYLES.read_text()

    assert '.policy-decision-card' in styles
    assert '.policy-facts' in styles
    assert '.policy-log-state[data-state="offline"]' in styles
    assert '.policy-log-state[data-state="no-match"]' in styles
    assert '.policy-log-state[data-state="reset"]' in styles
    assert '@media (max-width: 767px)' in styles
    assert '@media (max-width: 480px)' in styles
