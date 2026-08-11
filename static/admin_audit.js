(function() {
    'use strict';
    const root = document.getElementById('auditLog');
    if (!root) return;
    const body = document.getElementById('auditLogsBody');
    const tableWrap = document.getElementById('auditTableWrap');
    const empty = document.getElementById('auditEmpty');
    const loading = document.getElementById('auditLoading');
    const error = document.getElementById('auditError');
    const retry = document.getElementById('auditRetry');
    const loadMore = document.getElementById('auditLoadMore');
    const end = document.getElementById('auditEnd');
    const sentinel = document.getElementById('auditSentinel');
    if (!body || !tableWrap || !empty || !loading || !error || !retry || !loadMore || !end || !sentinel) return;
    let offset = Math.max(0, Number.parseInt(root.dataset.offset || '0', 10) || 0);
    const limit = Math.min(100, Math.max(1, Number.parseInt(root.dataset.limit || '25', 10) || 25));
    let hasMore = root.dataset.hasMore === 'true';
    let nextCursor = null;
    let pending = false;
    try { nextCursor = root.dataset.nextCursor ? JSON.parse(root.dataset.nextCursor) : null; } catch (parseError) { nextCursor = root.dataset.nextCursor || null; }

    function textCell(label, value, className) {
        const cell = document.createElement('td');
        cell.dataset.label = label;
        if (className) cell.className = className;
        cell.textContent = value || '-';
        return cell;
    }
    function actionTone(action) {
        if (action.includes('login')) return 'success';
        if (action.includes('delete') || action.includes('remove')) return 'danger';
        if (action.includes('create') || action.includes('add')) return 'primary';
        return 'neutral';
    }
    function appendLog(log) {
        const item = log && typeof log === 'object' ? log : {};
        const row = document.createElement('tr');
        row.className = 'compact-record';
        const timeCell = document.createElement('td');
        const time = document.createElement('time');
        timeCell.dataset.label = 'Time';
        time.className = 'text-nowrap';
        const date = item.timestamp ? new Date(item.timestamp) : null;
        if (date && !Number.isNaN(date.getTime())) { time.dateTime = date.toISOString(); time.textContent = date.toLocaleString(); } else { time.textContent = '-'; }
        timeCell.appendChild(time);
        const actionCell = document.createElement('td');
        const badge = document.createElement('span');
        const action = typeof item.action === 'string' ? item.action : '-';
        actionCell.dataset.label = 'Action';
        badge.className = 'admin-action-badge';
        badge.dataset.tone = actionTone(action);
        badge.textContent = action;
        actionCell.appendChild(badge);
        const ipCell = document.createElement('td');
        const code = document.createElement('code');
        ipCell.dataset.label = 'IP address';
        code.textContent = typeof item.ip_address === 'string' && item.ip_address ? item.ip_address : '-';
        ipCell.appendChild(code);
        const detailCell = textCell('Details', typeof item.details === 'string' ? item.details : '-', 'admin-audit-detail');
        detailCell.title = detailCell.textContent;
        row.append(timeCell, textCell('Operator', typeof item.username === 'string' ? item.username : 'system'), actionCell, detailCell, ipCell);
        body.appendChild(row);
    }
    function updateState() {
        const hasRows = body.children.length > 0;
        tableWrap.classList.toggle('d-none', !hasRows);
        empty.classList.toggle('d-none', hasRows || pending);
        loading.classList.toggle('d-none', !pending);
        loadMore.classList.toggle('d-none', !hasMore || pending);
        end.classList.toggle('d-none', hasMore || !hasRows || pending);
    }
    async function loadPage() {
        if (pending || !hasMore) return;
        pending = true;
        error.classList.add('d-none');
        updateState();
        const url = new URL(root.dataset.apiUrl || '/api/audit-logs', window.location.origin);
        const pageParams = new URLSearchParams(window.location.search);
        ['action', 'operator', 'text', 'system', 'date_from', 'date_to'].forEach(function(name) {
            if (pageParams.has(name)) url.searchParams.set(name, pageParams.get(name));
        });
        url.searchParams.set('limit', String(limit));
        if (nextCursor !== null) url.searchParams.set('cursor', typeof nextCursor === 'string' ? nextCursor : JSON.stringify(nextCursor));
        else url.searchParams.set('offset', String(offset));
        try {
            const response = await fetch(url.toString(), { headers: { Accept: 'application/json' } });
            if (!response.ok) throw new Error('Audit request failed');
            const data = await response.json();
            const logs = Array.isArray(data.logs) ? data.logs.slice(0, limit) : [];
            logs.forEach(appendLog);
            offset += logs.length;
            hasMore = Boolean(data.has_more);
            nextCursor = Object.prototype.hasOwnProperty.call(data, 'next_cursor') ? data.next_cursor : null;
            if (hasMore && logs.length === 0 && nextCursor === null) hasMore = false;
        } catch (requestError) { error.classList.remove('d-none'); }
        finally { pending = false; updateState(); }
    }
    retry.addEventListener('click', loadPage);
    loadMore.addEventListener('click', loadPage);
    if ('IntersectionObserver' in window) new IntersectionObserver(function(entries) { if (entries[0] && entries[0].isIntersecting) loadPage(); }, { rootMargin: '160px' }).observe(sentinel);
    updateState();
})();
