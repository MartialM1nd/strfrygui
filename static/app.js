(function() {
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
})();
