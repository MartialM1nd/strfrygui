(function() {
    'use strict';
    const manager = document.getElementById('relayManager');
    const body = document.getElementById('relaysBody');
    const tableWrap = document.getElementById('relayTableWrap');
    const loading = document.getElementById('relayLoading');
    const empty = document.getElementById('relayEmpty');
    const error = document.getElementById('relayError');
    const retry = document.getElementById('relayRetry');
    const status = document.getElementById('relayStatus');
    const addForm = document.getElementById('relayAddForm');
    const urlInput = document.getElementById('newRelayUrl');
    const mutationError = document.getElementById('relayMutationError');
    const deleteDialog = document.getElementById('relayDeleteDialog');
    const deleteTarget = document.getElementById('relayDeleteTarget');
    const deleteConfirm = document.getElementById('relayDeleteConfirm');
    const deleteSubmit = document.getElementById('relayDeleteSubmit');
    if (!manager || !body || !tableWrap || !loading || !empty || !error || !retry || !status || !addForm || !urlInput || !mutationError || !deleteDialog || !deleteTarget || !deleteConfirm || !deleteSubmit || typeof window.csrfFetch !== 'function') return;

    const apiUrl = '/api/metadata-relays';
    let pendingDelete = null;
    let loadGeneration = 0;

    function icon(name) {
        const element = document.createElement('i');
        element.className = 'bi ' + name;
        element.setAttribute('aria-hidden', 'true');
        return element;
    }
    function actionButton(label, iconName, className, handler) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn btn-sm ' + className;
        button.setAttribute('aria-label', label);
        button.title = label;
        button.appendChild(icon(iconName));
        button.addEventListener('click', handler);
        return button;
    }
    function showMutationError(message) {
        mutationError.textContent = message;
        mutationError.classList.toggle('d-none', !message);
    }
    async function request(url, options) {
        const response = await window.csrfFetch(url, options);
        let data = {};
        try { data = await response.json(); } catch (parseError) { data = {}; }
        if (!response.ok || data.error) throw new Error(data.error || 'The relay operation failed.');
        return data;
    }
    function setPending(button, value) {
        button.disabled = value;
        button.setAttribute('aria-busy', String(value));
    }
    function relayRow(relay) {
        const row = document.createElement('tr');
        row.className = 'compact-record';
        const healthCell = document.createElement('td');
        const relayCell = document.createElement('td');
        const testedCell = document.createElement('td');
        const controlsCell = document.createElement('td');
        const health = document.createElement('span');
        const url = document.createElement('code');
        const controls = document.createElement('div');
        const relayId = Number(relay.id);
        const relayUrl = typeof relay.url === 'string' ? relay.url : 'Unknown relay';

        health.className = 'admin-relay-health';
        health.dataset.status = ['success', 'failed'].includes(relay.last_status) ? relay.last_status : 'unknown';
        health.appendChild(icon(relay.last_status === 'success' ? 'bi-check-circle-fill' : relay.last_status === 'failed' ? 'bi-x-circle-fill' : 'bi-question-circle'));
        health.appendChild(document.createTextNode(relay.last_status === 'success' ? ' Working' : relay.last_status === 'failed' ? ' Failing' : ' Untested'));
        healthCell.dataset.label = 'Health';
        healthCell.appendChild(health);
        relayCell.dataset.label = 'Relay';
        url.className = 'operations-identifier';
        url.textContent = relayUrl;
        url.title = relayUrl;
        relayCell.appendChild(url);
        if (!relay.enabled) {
            const disabled = document.createElement('span');
            disabled.className = 'badge text-bg-secondary ms-2';
            disabled.textContent = 'Disabled';
            relayCell.appendChild(disabled);
        }
        testedCell.dataset.label = 'Last tested';
        if (relay.last_tested) {
            const date = new Date(relay.last_tested);
            testedCell.textContent = Number.isNaN(date.getTime()) ? 'Unknown' : date.toLocaleString();
        } else testedCell.textContent = 'Never';
        controlsCell.dataset.label = 'Controls';
        controlsCell.className = 'text-end';
        controls.className = 'admin-relay-controls';
        controls.append(
            actionButton('Test ' + relayUrl, 'bi-arrow-repeat', 'btn-outline-primary', async function(event) {
                const button = event.currentTarget;
                setPending(button, true);
                showMutationError('');
                try {
                    const result = await request(apiUrl + '/' + relayId + '/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
                    await loadRelays();
                    if (result.status !== 'success') showMutationError(result.message || 'Relay test failed.');
                } catch (requestError) { showMutationError(requestError.message); await loadRelays(); }
            }),
            actionButton((relay.enabled ? 'Disable ' : 'Enable ') + relayUrl, relay.enabled ? 'bi-toggle-on' : 'bi-toggle-off', 'btn-outline-secondary', async function(event) {
                const button = event.currentTarget;
                setPending(button, true);
                showMutationError('');
                try { await request(apiUrl + '/' + relayId + '/toggle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); await loadRelays(); }
                catch (requestError) { showMutationError(requestError.message); setPending(button, false); }
            }),
            actionButton('Delete ' + relayUrl, 'bi-trash', 'btn-outline-danger', function() {
                pendingDelete = { id: relayId, url: relayUrl };
                deleteTarget.textContent = relayUrl;
                deleteConfirm.value = '';
                deleteSubmit.disabled = true;
                deleteDialog.showModal();
            })
        );
        controlsCell.appendChild(controls);
        row.append(healthCell, relayCell, testedCell, controlsCell);
        return row;
    }
    async function loadRelays() {
        const generation = ++loadGeneration;
        manager.setAttribute('aria-busy', 'true');
        loading.classList.remove('d-none');
        error.classList.add('d-none');
        tableWrap.classList.add('d-none');
        empty.classList.add('d-none');
        try {
            const response = await fetch(apiUrl, { headers: { Accept: 'application/json' } });
            if (!response.ok) throw new Error('Metadata relays could not be loaded.');
            const data = await response.json();
            if (generation !== loadGeneration) return;
            const relays = Array.isArray(data) ? data : [];
            body.replaceChildren(...relays.map(relayRow));
            const failed = relays.filter(function(relay) { return relay.last_status === 'failed'; }).length;
            status.textContent = relays.length === 0 ? 'No relays' : failed ? failed + ' failing' : relays.length + ' configured';
            status.dataset.tone = failed ? 'danger' : relays.length ? 'success' : 'neutral';
            tableWrap.classList.toggle('d-none', relays.length === 0);
            empty.classList.toggle('d-none', relays.length !== 0);
        } catch (requestError) {
            if (generation !== loadGeneration) return;
            error.classList.remove('d-none');
            status.textContent = 'Unavailable';
            status.dataset.tone = 'danger';
        } finally {
            if (generation !== loadGeneration) return;
            loading.classList.add('d-none');
            manager.setAttribute('aria-busy', 'false');
        }
    }
    addForm.addEventListener('submit', async function(event) {
        event.preventDefault();
        if (!addForm.reportValidity()) return;
        const button = addForm.querySelector('button[type="submit"]');
        if (!button) return;
        setPending(button, true);
        showMutationError('');
        try {
            await request(apiUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: urlInput.value.trim() }) });
            addForm.reset();
            await loadRelays();
        } catch (requestError) { showMutationError(requestError.message); }
        finally { setPending(button, false); }
    });
    deleteDialog.addEventListener('close', async function() {
        if (deleteDialog.returnValue !== 'default' || !pendingDelete) { pendingDelete = null; return; }
        if (deleteConfirm.value !== pendingDelete.url) { showMutationError('Type the exact relay URL before deleting it.'); pendingDelete = null; return; }
        const target = pendingDelete;
        pendingDelete = null;
        showMutationError('');
        try {
            await request(apiUrl + '/' + target.id, {
                method: 'DELETE',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ confirm_url: target.url })
            });
            await loadRelays();
        }
        catch (requestError) { showMutationError(requestError.message); }
    });
    deleteConfirm.addEventListener('input', function() { deleteSubmit.disabled = !pendingDelete || deleteConfirm.value !== pendingDelete.url; });
    retry.addEventListener('click', loadRelays);
    loadRelays();
})();
