from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVENTS = (ROOT / "templates" / "events.html").read_text()
MODERATION = (ROOT / "templates" / "moderation.html").read_text()
STYLES = (ROOT / "static" / "style.css").read_text()


def test_event_query_builder_tracks_query_state_and_keeps_controls():
    assert 'class="dashboard-panel event-query-panel mb-4"' in EVENTS
    assert 'is-expanded' not in EVENTS
    assert 'id="eventQueryBuilder" class="collapse{% if not search_performed or error %} show{% endif %}" data-responsive-disclosure' in EVENTS
    assert 'class="event-query-summary" aria-label="Current query"' in EVENTS
    assert 'data-bs-target="#eventQueryBuilder"' in EVENTS
    assert 'type="submit" form="searchForm"' in EVENTS
    assert 'href="{{ url_for(\'events\') }}"' in EVENTS
    assert 'id="eventSelectionBar" aria-live="polite"' in EVENTS
    assert "bar.classList.toggle('d-none', ids.length === 0)" in EVENTS
    assert 'id="selectAllEvents"' in EVENTS
    assert "document.querySelectorAll('.event-checkbox')" in EVENTS


def test_event_rows_keep_compact_content_identifiers_and_sensitive_details():
    assert 'class="event-result-card compact-record' in EVENTS
    assert 'class="operations-identifier event-identifier"' in EVENTS
    assert 'title="{{ event_pubkey }}"' in EVENTS
    assert 'class="event-detail-identifier"' in EVENTS
    assert 'title="{{ event_id }}"' in EVENTS
    assert 'data-event-action="reveal"' in EVENTS
    assert 'data-bs-toggle="collapse"' in EVENTS
    assert 'data-event-action="delete"' in EVENTS
    assert 'data-event-action="ban"' in EVENTS


def test_event_author_ban_posts_csrf_token_in_form_body():
    assert "const csrfToken = document.querySelector('meta[name=\"csrf-token\"]')?.content || '';" in EVENTS
    assert 'new URLSearchParams({ csrf_token: csrfToken, pubkey: pendingEventAction.pubkey, reason })' in EVENTS
    assert "headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }" in EVENTS
    assert 'await readJsonResponse(response' in EVENTS


def test_moderation_static_and_dynamic_reports_share_compact_structure():
    assert 'class="moderation-kpi-strip mb-4"' in MODERATION
    assert 'class="moderation-filter-bar compact-toolbar mb-4"' in MODERATION
    assert 'class="moderation-report-card compact-record' in MODERATION
    assert "node('article', 'moderation-report-card compact-record')" in MODERATION
    assert "link.title = value" in MODERATION
    assert "node('code', 'moderation-detail-identifier'" in MODERATION
    assert 'class="moderation-detail-identifier"' in MODERATION
    assert "confirm('Delete this moderation report?')" in MODERATION
    assert "confirm('Purge this reported event? This cannot be undone.')" in MODERATION
    assert 'Event purge operations' in MODERATION
    assert 'Domain ban operations' in MODERATION
    assert "detailsButton.setAttribute('aria-expanded', 'false')" in MODERATION


def test_moderation_report_details_link_to_and_preview_reported_event():
    assert "url_for('events', search_type='event_id', event_id=report.reported_event_id)" in MODERATION
    assert "url_for('events', search_type='event_id', event_id=report.event_id)" in MODERATION
    assert 'class="moderation-event-link"' in MODERATION
    assert "node('a', 'moderation-event-link'" in MODERATION
    assert 'data-event-id="{{ report.reported_event_id or report.event_id }}"' in MODERATION
    assert "const previewEventId = report.reported_event_id || report.event_id;" in MODERATION
    assert "report.reported_event_id ? 'Reported event preview' : 'Report event preview'" in MODERATION
    assert 'data-report-details' in MODERATION
    assert "event.target.closest('[data-report-details]')" in MODERATION
    assert 'loadReportEventPreview(detail)' in MODERATION


def test_compact_density_is_desktop_only_and_mobile_safeguards_remain():
    desktop_start = STYLES.index('@media (min-width: 992px)')
    desktop = STYLES[desktop_start:]

    assert '.event-shell .compact-record' in desktop
    assert '.moderation-shell .compact-record' in desktop
    assert 'min-height: 84px' in desktop
    assert 'contain-intrinsic-size: auto 96px' in desktop
    assert '-webkit-line-clamp: 2' in desktop
    assert '.moderation-shell .moderation-kpi-strip' in desktop
    assert '.moderation-shell .compact-toolbar' in desktop
    assert 'flex-direction: row' in desktop
    assert '@media (max-width: 991px)' in STYLES[:desktop_start]
    assert '.event-result-main { grid-template-columns: 1fr; }' in STYLES[:desktop_start]
    assert '.moderation-report-main { grid-template-columns: 1fr; }' in STYLES[:desktop_start]
    assert '.event-result-actions .btn { flex: 1 1 100%; min-height: 42px; }' in STYLES[:desktop_start]
    assert '.moderation-report-actions .btn { flex: 1 1 100%; min-height: 42px; }' in STYLES[:desktop_start]
    assert '.event-query-panel:has(#eventQueryBuilder.show) .event-query-heading' in desktop
    assert '.moderation-shell .moderation-report-reason,\n    .moderation-shell .moderation-report-context { grid-column: auto; }' in desktop
    assert 'class="event-query-more" data-responsive-disclosure' not in EVENTS
    assert 'class="moderation-operation mb-3" data-responsive-disclosure' not in MODERATION
