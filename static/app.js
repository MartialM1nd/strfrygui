(function() {
    document.addEventListener('click', function(event) {
        const control = typeof event.target.closest === 'function' ? event.target.closest('[data-confirm]') : null;
        if (control && !window.confirm(control.getAttribute('data-confirm'))) {
            event.preventDefault();
        }
    });

    window.csrfFetch = function(url, options) {
        const requestOptions = { ...(options || {}) };
        const method = String(requestOptions.method || 'GET').toUpperCase();
        if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
            const headers = new Headers(requestOptions.headers || {});
            const token = document.querySelector('meta[name="csrf-token"]');
            if (token) headers.set('X-CSRFToken', token.content);
            requestOptions.headers = headers;
        }
        return fetch(url, requestOptions);
    };

    window.readJsonResponse = async function(response, fallbackMessage) {
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            const status = response.status ? ` (HTTP ${response.status})` : '';
            throw new Error(`${fallbackMessage}${status}`);
        }
        let data;
        try {
            data = await response.json();
        } catch (error) {
            throw new Error(fallbackMessage);
        }
        if (!response.ok) {
            const message = data && typeof data.error === 'string' ? data.error : fallbackMessage;
            throw new Error(message);
        }
        return data;
    };

    const html = document.documentElement;
    const icon = document.getElementById('themeIcon');
    const toggle = document.getElementById('themeToggle');
    let stored = null;
    try {
        stored = localStorage.getItem('theme');
    } catch (error) {
        stored = null;
    }
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = stored || (prefersDark ? 'dark' : 'light');

    function updateTheme(nextTheme) {
        html.setAttribute('data-bs-theme', nextTheme);
        if (icon) icon.className = nextTheme === 'dark' ? 'bi bi-moon-fill' : 'bi bi-sun-fill';
        if (toggle) toggle.setAttribute('aria-pressed', String(nextTheme === 'dark'));
    }

    updateTheme(theme);
    if (toggle) {
        toggle.addEventListener('click', function() {
            const next = html.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
            try {
                localStorage.setItem('theme', next);
            } catch (error) {
                // Theme still applies for this page when storage is unavailable.
            }
            updateTheme(next);
        });
    }

    const responsiveDisclosures = Array.from(document.querySelectorAll('[data-responsive-disclosure]'));
    if (!responsiveDisclosures.length) return;

    const mobileDisclosures = window.matchMedia('(max-width: 991px)');
    const desktopDefaults = new Map(responsiveDisclosures.map(function(disclosure) {
        return [disclosure, disclosure.tagName === 'DETAILS' ? disclosure.open : disclosure.classList.contains('show')];
    }));
    let mobileState = null;

    function collapseControls(disclosure) {
        if (!disclosure.id) return [];
        return Array.from(document.querySelectorAll('[data-bs-toggle="collapse"]')).filter(function(control) {
            return control.getAttribute('data-bs-target') === '#' + disclosure.id;
        });
    }

    function setDisclosureOpen(disclosure, open) {
        if (disclosure.tagName === 'DETAILS') {
            disclosure.open = open;
            return;
        }
        disclosure.classList.remove('collapsing');
        disclosure.classList.toggle('show', open);
        collapseControls(disclosure).forEach(function(control) {
            control.setAttribute('aria-expanded', String(open));
            control.classList.toggle('collapsed', !open);
        });
    }

    function updateResponsiveDisclosures() {
        if (mobileState === mobileDisclosures.matches) return;
        mobileState = mobileDisclosures.matches;
        responsiveDisclosures.forEach(function(disclosure) {
            setDisclosureOpen(disclosure, mobileState || desktopDefaults.get(disclosure));
        });
    }

    document.addEventListener('click', function(event) {
        const summary = typeof event.target.closest === 'function' ? event.target.closest('summary') : null;
        if (mobileDisclosures.matches && summary && summary.parentElement.matches('details[data-responsive-disclosure]')) {
            event.preventDefault();
        }
    });
    document.addEventListener('hide.bs.collapse', function(event) {
        if (mobileDisclosures.matches && typeof event.target.matches === 'function' && event.target.matches('[data-responsive-disclosure]')) {
            event.preventDefault();
        }
    });
    if (typeof mobileDisclosures.addEventListener === 'function') {
        mobileDisclosures.addEventListener('change', updateResponsiveDisclosures);
    } else {
        mobileDisclosures.addListener(updateResponsiveDisclosures);
    }
    updateResponsiveDisclosures();
})();
