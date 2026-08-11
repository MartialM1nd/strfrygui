from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADMIN_BASE = (ROOT / 'templates' / 'admin_base.html').read_text()
AUDIT = (ROOT / 'templates' / 'admin_audit.html').read_text()
OPERATORS = (ROOT / 'templates' / 'admin_operators.html').read_text()
RELAYS = (ROOT / 'templates' / 'admin_relays.html').read_text()
BANS = (ROOT / 'templates' / 'admin_bans.html').read_text()
DOMAIN = (ROOT / 'templates' / 'moderation_domain_details.html').read_text()
AUDIT_JS = (ROOT / 'static' / 'admin_audit.js').read_text()
RELAYS_JS = (ROOT / 'static' / 'admin_relays.js').read_text()
APP_JS = (ROOT / 'static' / 'app.js').read_text()
STYLES = (ROOT / 'static' / 'style.css').read_text()


def test_admin_surfaces_opt_into_compact_desktop_structure():
    assert 'admin-masthead' in ADMIN_BASE
    assert 'class="dashboard-panel admin-filter-disclosure compact-panel mb-4" data-responsive-disclosure' in AUDIT
    assert '{% if active_filters.count %} open{% endif %}' in AUDIT
    assert 'class="dashboard-panel admin-operator-card compact-record"' in OPERATORS
    assert '{% if create_user_form.errors %} open{% endif %}' in OPERATORS
    assert 'class="dashboard-panel admin-relay-disclosure mb-3" data-responsive-disclosure' in RELAYS
    assert 'admin-registry-item compact-record' in BANS


def test_static_and_appended_admin_rows_have_compact_detail_parity():
    assert '<tr class="compact-record">' in AUDIT
    assert 'class="admin-audit-detail" title="{{ log.details or \'-\' }}"' in AUDIT
    assert "row.className = 'compact-record'" in AUDIT_JS
    assert "detailCell.title = detailCell.textContent" in AUDIT_JS
    assert "row.className = 'compact-record'" in RELAYS_JS
    assert "url.title = relayUrl" in RELAYS_JS


def test_relay_mutation_errors_are_not_hidden_inside_add_disclosure():
    disclosure_end = RELAYS.index('</details>')
    mutation_error = RELAYS.index('id="relayMutationError"')

    assert mutation_error > disclosure_end
    assert 'role="alert"' in RELAYS[mutation_error:mutation_error + 100]
    assert "showMutationError(result.message || 'Relay test failed.')" in RELAYS_JS
    assert "catch (requestError) { showMutationError(requestError.message);" in RELAYS_JS


def test_shared_responsive_controller_preserves_desktop_defaults_and_forces_mobile_open():
    assert "querySelectorAll('[data-responsive-disclosure]')" in APP_JS
    assert "window.matchMedia('(max-width: 991px)')" in APP_JS
    assert 'desktopDefaults = new Map' in APP_JS
    assert 'mobileState || desktopDefaults.get(disclosure)' in APP_JS
    assert "event.preventDefault()" in APP_JS
    assert "details[data-responsive-disclosure]" in APP_JS
    assert 'class="admin-disclosure" data-responsive-disclosure' not in OPERATORS
    assert 'class="admin-disclosure admin-confirmation" data-responsive-disclosure' not in BANS


def test_domain_rows_keep_copy_title_and_dual_pagination_accessibility():
    assert 'domain-kpi-strip' in DOMAIN
    assert 'domain-results-toolbar compact-toolbar' in DOMAIN
    assert DOMAIN.count('class="domain-pagination"') == 2
    assert 'aria-label="Verified identities pages"' in DOMAIN
    assert 'aria-label="Unresolved identities pages"' in DOMAIN
    assert 'title="{{ row.npub }}"' in DOMAIN
    assert 'title="{{ source.banned_pubkey.pubkey }}"' in DOMAIN
    assert 'title="{{ entry.pubkey }}"' in DOMAIN
    assert 'aria-live="polite"' in DOMAIN


def test_admin_and_domain_density_is_desktop_only_with_mobile_safeguards():
    desktop_start = STYLES.index('@media (min-width: 992px)')
    desktop = STYLES[desktop_start:]
    mobile = STYLES[:desktop_start]

    assert '.admin-shell .admin-masthead' in desktop
    assert '.admin-shell .admin-table thead' in desktop
    assert 'position: sticky' in desktop
    assert '-webkit-line-clamp: 2' in desktop
    assert '.admin-shell .admin-operator-card' in desktop
    assert '.admin-shell .admin-registry-item' in desktop
    assert '.domain-operations-shell .domain-kpi-strip' in desktop
    assert '.domain-operations-shell .domain-copy-cell code' in desktop
    assert '@media (max-width: 991px)' in mobile
    assert 'min-height: 42px' in mobile
    assert '.admin-table thead { display: none; }' in mobile
    assert '.admin-table td::before' in mobile
    assert '.admin-table .btn { min-width: 42px; min-height: 42px; }' in mobile
    assert '.domain-copy-cell .copy-value { min-width: 42px; min-height: 42px; }' in mobile
    assert '.domain-filter-actions .btn, .domain-header-actions .btn' in mobile
