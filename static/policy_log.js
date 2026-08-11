(function () {
    'use strict';

    const MAX_RETAINED_RECORDS = 1000;
    const MAX_BATCH_RECORDS = 500;
    const MAX_CATCHUP_POLLS = 4;
    const POLL_INTERVAL_MS = 2500;
    const CATCHUP_DELAY_MS = 100;
    const REQUEST_TIMEOUT_MS = 8000;
    const MAX_RETRY_DELAY_MS = 30000;
    const STALE_AFTER_MS = 15000;

    const shell = document.getElementById('policyLogApp');
    if (!shell) return;

    const decisionList = document.getElementById('decisionList');
    const policyState = document.getElementById('policyState');
    const policyStateIcon = document.getElementById('policyStateIcon');
    const policyStateTitle = document.getElementById('policyStateTitle');
    const policyStateMessage = document.getElementById('policyStateMessage');
    const feedStatus = document.getElementById('feedStatus');
    const feedStatusText = document.getElementById('feedStatusText');
    const feedFreshness = document.getElementById('feedFreshness');
    const feedWarning = document.getElementById('feedWarning');
    const resetNotice = document.getElementById('resetNotice');
    const visibleCount = document.getElementById('visibleCount');
    const pauseButton = document.getElementById('pauseButton');
    const pauseButtonText = pauseButton.querySelector('span');
    const pauseButtonIcon = pauseButton.querySelector('i');
    const filterIds = [
        'actionFilter', 'simulatedFilter', 'reasonFilter', 'kindFilter',
        'sourceTypeFilter', 'sourceIpFilter', 'eventIdFilter', 'pubkeyFilter'
    ];
    const filters = Object.fromEntries(filterIds.map(function (id) {
        return [id, document.getElementById(id)];
    }));

    let records = [];
    let cursor = null;
    let paused = false;
    let available = null;
    let offlineMessage = '';
    let resetState = false;
    let viewCleared = false;
    let latestLogTimestamp = null;
    let lastSuccessfulPoll = null;
    let retryDelay = 2000;
    let catchupPolls = 0;
    let pollTimer = null;
    let requestController = null;
    let resumeAfterRequest = false;

    function setFeedStatus(label, status) {
        feedStatusText.textContent = label;
        feedStatus.dataset.status = status;
    }

    function setWarning(message) {
        feedWarning.textContent = message;
        feedWarning.classList.toggle('d-none', !message);
    }

    function setState(name, icon, title, message) {
        policyState.dataset.state = name;
        policyStateIcon.className = 'bi ' + icon;
        policyStateTitle.textContent = title;
        policyStateMessage.textContent = message;
        policyState.classList.remove('d-none');
    }

    function hideState() {
        policyState.classList.add('d-none');
    }

    function formatReason(value) {
        return value ? value.replaceAll('_', ' ') : 'Not recorded';
    }

    function formatAge(timestamp) {
        const elapsedSeconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
        if (elapsedSeconds < 2) return 'just now';
        if (elapsedSeconds < 60) return elapsedSeconds + ' seconds ago';
        const elapsedMinutes = Math.floor(elapsedSeconds / 60);
        if (elapsedMinutes < 60) return elapsedMinutes + (elapsedMinutes === 1 ? ' minute ago' : ' minutes ago');
        const elapsedHours = Math.floor(elapsedMinutes / 60);
        return elapsedHours + (elapsedHours === 1 ? ' hour ago' : ' hours ago');
    }

    function updateFreshness() {
        if (latestLogTimestamp !== null) {
            feedFreshness.textContent = 'Policy log updated ' + formatAge(latestLogTimestamp);
        } else if (lastSuccessfulPoll !== null) {
            feedFreshness.textContent = 'Connected ' + formatAge(lastSuccessfulPoll) + ' · no decisions recorded';
        } else {
            feedFreshness.textContent = 'Waiting for the policy log';
        }

        if (paused) {
            setFeedStatus('Feed paused', 'stale');
        } else if (document.hidden) {
            setFeedStatus('Background paused', 'stale');
        } else if (offlineMessage || available === false) {
            setFeedStatus(available === false ? 'Log unavailable' : 'Offline', 'offline');
        } else if (available === true && lastSuccessfulPoll !== null) {
            const stale = Date.now() - lastSuccessfulPoll > STALE_AFTER_MS;
            setFeedStatus(stale ? 'Connection stale' : 'Live', stale ? 'stale' : 'healthy');
        }
    }

    function createOutcome(value, simulated) {
        const badge = document.createElement('span');
        badge.className = 'policy-outcome';
        if (!value) {
            badge.dataset.outcome = 'none';
            badge.textContent = 'Not simulated';
        } else {
            badge.dataset.outcome = value;
            badge.textContent = simulated
                ? (value === 'accept' ? 'Would accept' : 'Would reject')
                : (value === 'accept' ? 'Accepted' : 'Rejected');
        }
        return badge;
    }

    function createFact(label, value, className) {
        const fact = document.createElement('div');
        fact.className = 'policy-fact' + (className ? ' ' + className : '');
        const name = document.createElement('span');
        name.textContent = label;
        const content = document.createElement('strong');
        content.textContent = value;
        fact.append(name, content);
        return fact;
    }

    function createExplorerLink(prefix, value, searchType, parameter) {
        const row = document.createElement('div');
        row.className = 'policy-identifier-row';
        const label = document.createElement('span');
        label.textContent = prefix + ':';
        row.appendChild(label);
        if (!value) {
            const missing = document.createElement('span');
            missing.textContent = 'Not recorded';
            row.appendChild(missing);
            return row;
        }
        const url = new URL(shell.dataset.eventsUrl, window.location.origin);
        url.searchParams.set('search_type', searchType);
        url.searchParams.set(parameter, value);
        const link = document.createElement('a');
        link.href = url.pathname + url.search;
        link.title = value;
        link.setAttribute(
            'aria-label',
            (searchType === 'event_id' ? 'Open event in Event Explorer: ' : 'Open author in Event Explorer: ') + value
        );
        link.textContent = value;
        row.appendChild(link);
        return row;
    }

    function createDecisionCard(record) {
        const card = document.createElement('article');
        card.className = 'policy-decision-card compact-record';
        card.dataset.outcome = record.action;

        const top = document.createElement('div');
        top.className = 'policy-decision-top';
        const outcomes = document.createElement('div');
        outcomes.className = 'policy-outcomes';
        outcomes.append(createOutcome(record.action, false), createOutcome(record.simulated_action, true));
        const time = document.createElement('time');
        time.dateTime = new Date(record.timestamp_ms).toISOString();
        time.textContent = new Date(record.timestamp_ms).toLocaleString();
        top.append(outcomes, time);

        const facts = document.createElement('div');
        facts.className = 'policy-facts';
        facts.append(
            createFact('Actual reason', formatReason(record.reason), 'policy-fact-actual-reason'),
            createFact('Monitor reason', formatReason(record.simulated_reason), 'policy-fact-monitor-reason'),
            createFact('Event kind', record.kind === null ? 'Not recorded' : String(record.kind), 'policy-fact-kind'),
            createFact('Source', [record.source_type, record.source_ip].filter(Boolean).join(' · ') || 'Not recorded', 'policy-fact-source'),
            createFact('Policy mode', record.policy_mode || 'Not recorded', 'policy-fact-mode')
        );

        const identifiers = document.createElement('div');
        identifiers.className = 'policy-identifiers';
        identifiers.append(
            createExplorerLink('Event', record.event_id, 'event_id', 'event_id'),
            createExplorerLink('Author', record.pubkey, 'pubkey', 'pubkey')
        );
        card.append(top, facts, identifiers);
        return card;
    }

    function includesFilter(value, query) {
        return String(value || '').toLowerCase().includes(query);
    }

    function matchesFilters(record) {
        const action = filters.actionFilter.value;
        const simulated = filters.simulatedFilter.value;
        const reason = filters.reasonFilter.value;
        const kind = filters.kindFilter.value;
        const sourceType = filters.sourceTypeFilter.value.trim().toLowerCase();
        const sourceIp = filters.sourceIpFilter.value.trim().toLowerCase();
        const eventId = filters.eventIdFilter.value.trim().toLowerCase();
        const pubkey = filters.pubkeyFilter.value.trim().toLowerCase();
        if (action && record.action !== action) return false;
        if (simulated === 'none' && record.simulated_action !== null) return false;
        if (simulated && simulated !== 'none' && record.simulated_action !== simulated) return false;
        if (reason && record.reason !== reason && record.simulated_reason !== reason) return false;
        if (kind && String(record.kind) !== kind) return false;
        if (sourceType && !includesFilter(record.source_type, sourceType)) return false;
        if (sourceIp && !includesFilter(record.source_ip, sourceIp)) return false;
        if (eventId && !includesFilter(record.event_id, eventId)) return false;
        if (pubkey && !includesFilter(record.pubkey, pubkey)) return false;
        return true;
    }

    function hasActiveFilters() {
        return filterIds.some(function (id) { return filters[id].value !== ''; });
    }

    function render() {
        decisionList.replaceChildren();
        const filtered = records.filter(matchesFilters).slice().reverse();
        const fragment = document.createDocumentFragment();
        filtered.forEach(function (record) { fragment.appendChild(createDecisionCard(record)); });
        decisionList.appendChild(fragment);
        visibleCount.textContent = filtered.length + ' visible · ' + records.length + ' retained in browser';

        if (filtered.length > 0) {
            hideState();
        } else if (offlineMessage || available === false) {
            setState('offline', 'bi-cloud-slash', 'Policy log unavailable', offlineMessage || 'The runtime log cannot be read. Check runtime directory and service group permissions.');
        } else if (records.length > 0 && hasActiveFilters()) {
            setState('no-match', 'bi-funnel', 'No matching decisions', 'Clear or adjust filters to see retained decisions.');
        } else if (resetState) {
            setState('reset', 'bi-arrow-repeat', 'Policy log reset', 'The log changed on disk. Waiting for decisions from the new log.');
        } else if (viewCleared) {
            setState('cleared', 'bi-trash3', 'Browser view cleared', 'The live cursor was preserved. New decisions will appear here.');
        } else {
            setState('empty', 'bi-hourglass-split', 'Waiting for decisions', 'New write-policy decisions will appear here.');
        }
    }

    function assertNullableString(value, field, maximum) {
        if (value !== null && (typeof value !== 'string' || value.length > maximum)) {
            throw new Error('Invalid policy log event field: ' + field);
        }
    }

    function validateEvent(record) {
        if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('Invalid policy log event');
        if (
            !Number.isSafeInteger(record.timestamp_ms)
            || record.timestamp_ms < 0
            || !Number.isFinite(new Date(record.timestamp_ms).getTime())
        ) throw new Error('Invalid policy log event timestamp');
        if (record.action !== 'accept' && record.action !== 'reject') throw new Error('Invalid policy log event action');
        if (record.simulated_action !== null && record.simulated_action !== 'accept' && record.simulated_action !== 'reject') {
            throw new Error('Invalid policy log simulated action');
        }
        if (record.kind !== null && !Number.isSafeInteger(record.kind)) throw new Error('Invalid policy log event kind');
        assertNullableString(record.reason, 'reason', 64);
        assertNullableString(record.simulated_reason, 'simulated_reason', 64);
        assertNullableString(record.event_id, 'event_id', 128);
        assertNullableString(record.pubkey, 'pubkey', 128);
        assertNullableString(record.source_ip, 'source_ip', 64);
        assertNullableString(record.source_type, 'source_type', 32);
        assertNullableString(record.policy_mode, 'policy_mode', 16);
        return record;
    }

    function validateBatch(data) {
        if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid policy log response');
        if (!Array.isArray(data.events) || data.events.length > MAX_BATCH_RECORDS) throw new Error('Invalid policy log events');
        if (data.cursor !== null && (typeof data.cursor !== 'string' || data.cursor.length > 128)) throw new Error('Invalid policy log cursor');
        if (typeof data.reset !== 'boolean' || typeof data.has_more !== 'boolean' || typeof data.available !== 'boolean') {
            throw new Error('Invalid policy log response flags');
        }
        if (data.updated_at !== null && (!Number.isSafeInteger(data.updated_at) || data.updated_at < 0)) {
            throw new Error('Invalid policy log update time');
        }
        data.events.forEach(validateEvent);
        return data;
    }

    function pollingAllowed() {
        return !paused && !document.hidden;
    }

    function schedulePoll(delay) {
        window.clearTimeout(pollTimer);
        pollTimer = null;
        if (!pollingAllowed()) return;
        pollTimer = window.setTimeout(loadDecisions, delay);
    }

    function stopCurrentRequest(resumeWhenAllowed) {
        window.clearTimeout(pollTimer);
        pollTimer = null;
        resumeAfterRequest = resumeWhenAllowed;
        if (requestController) requestController.abort();
    }

    async function loadDecisions() {
        if (requestController || !pollingAllowed()) return;
        const controller = new AbortController();
        requestController = controller;
        let timedOut = false;
        const timeout = window.setTimeout(function () {
            timedOut = true;
            controller.abort();
        }, REQUEST_TIMEOUT_MS);
        setFeedStatus('Updating', 'stale');

        try {
            const url = new URL(shell.dataset.apiUrl, window.location.origin);
            url.searchParams.set('limit', String(MAX_BATCH_RECORDS));
            if (cursor) url.searchParams.set('cursor', cursor);
            const response = await fetch(url.pathname + url.search, {
                headers: { 'Accept': 'application/json' },
                cache: 'no-store',
                signal: controller.signal
            });
            const contentType = response.headers.get('content-type') || '';
            if (!response.ok || response.redirected || !contentType.includes('application/json')) {
                throw new Error('Policy log request was not authorized or returned invalid data.');
            }
            const data = validateBatch(await response.json());
            if (!pollingAllowed() || controller.signal.aborted) return;

            resetState = data.reset;
            resetNotice.classList.toggle('d-none', !data.reset);
            if (data.reset) records = [];
            if (data.events.length > 0) {
                records.push(...data.events);
                viewCleared = false;
            }
            if (records.length > MAX_RETAINED_RECORDS) records = records.slice(-MAX_RETAINED_RECORDS);
            cursor = data.cursor;
            available = data.available;
            latestLogTimestamp = data.updated_at;
            lastSuccessfulPoll = Date.now();
            offlineMessage = '';
            retryDelay = 2000;
            setWarning(data.available ? '' : 'The runtime policy log is unavailable. Verify the shared runtime directory and service group permissions.');
            render();
            updateFreshness();

            if (data.has_more) {
                catchupPolls += 1;
                const delay = catchupPolls < MAX_CATCHUP_POLLS ? CATCHUP_DELAY_MS : POLL_INTERVAL_MS;
                if (catchupPolls >= MAX_CATCHUP_POLLS) catchupPolls = 0;
                schedulePoll(delay);
            } else {
                catchupPolls = 0;
                schedulePoll(POLL_INTERVAL_MS);
            }
        } catch (error) {
            if (error.name === 'AbortError' && !timedOut) return;
            offlineMessage = timedOut ? 'The policy log request timed out.' : 'The policy log could not be reached.';
            available = null;
            setWarning(offlineMessage);
            render();
            updateFreshness();
            retryDelay = Math.min(retryDelay * 2, MAX_RETRY_DELAY_MS);
            schedulePoll(retryDelay);
        } finally {
            window.clearTimeout(timeout);
            if (requestController === controller) requestController = null;
            if (resumeAfterRequest && pollingAllowed()) {
                resumeAfterRequest = false;
                schedulePoll(0);
            }
        }
    }

    filterIds.forEach(function (id) { filters[id].addEventListener('input', render); });
    document.getElementById('clearFiltersButton').addEventListener('click', function () {
        filterIds.forEach(function (id) { filters[id].value = ''; });
        render();
    });
    document.getElementById('clearViewButton').addEventListener('click', function () {
        records = [];
        resetState = false;
        viewCleared = true;
        resetNotice.classList.add('d-none');
        render();
    });
    pauseButton.addEventListener('click', function () {
        paused = !paused;
        pauseButton.setAttribute('aria-pressed', String(paused));
        pauseButtonText.textContent = paused ? 'Resume feed' : 'Pause feed';
        pauseButtonIcon.className = paused ? 'bi bi-play-fill' : 'bi bi-pause-fill';
        if (paused) stopCurrentRequest(false);
        else if (requestController) resumeAfterRequest = true;
        else schedulePoll(0);
        updateFreshness();
    });
    document.addEventListener('visibilitychange', function () {
        if (document.hidden) stopCurrentRequest(false);
        else if (!paused && requestController) resumeAfterRequest = true;
        else if (!paused) schedulePoll(0);
        updateFreshness();
    });

    render();
    updateFreshness();
    window.setInterval(updateFreshness, 1000);
    schedulePoll(0);
}());
