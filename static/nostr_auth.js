(function() {
    const shell = document.querySelector('[data-nostr-auth]');
    const button = document.getElementById('nostrAuthButton');
    const status = document.getElementById('nostrAuthStatus');
    if (!shell || !button || !status) return;

    const action = shell.dataset.nostrAuth;

    function show(message, category) {
        status.textContent = message;
        status.className = `alert alert-${category || 'info'}`;
    }

    function encodeEvent(event) {
        const bytes = new TextEncoder().encode(JSON.stringify(event));
        let binary = '';
        bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
        return btoa(binary);
    }

    function setupPayload() {
        if (action !== 'bootstrap') return {};
        return {
            registration_token: document.getElementById('setupRegistrationToken').value,
        };
    }

    async function authenticate() {
        const payload = setupPayload();
        if (action === 'bootstrap' && !payload.registration_token) {
            show('Enter the registration token.', 'warning');
            return;
        }
        button.disabled = true;
        show('Requesting a one-time challenge...', 'info');
        try {
            const challengeResponse = await window.csrfFetch('/api/auth/challenge', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action, next: shell.dataset.next || null, ...payload }),
            });
            const challenge = await challengeResponse.json();
            if (!challengeResponse.ok) throw new Error(challenge.error || 'Could not create a challenge.');

            show('Approve the authentication request in your Nostr extension.', 'info');
            const signedEvent = await window.nostr.signEvent(challenge.event);
            const endpoints = {
                login: '/api/auth/verify',
                bootstrap: '/api/auth/bootstrap',
                'rotate-key': '/api/auth/rotate-key',
            };
            const verifyResponse = await window.csrfFetch(endpoints[action], {
                method: 'POST',
                headers: {
                    Authorization: `Nostr ${encodeEvent(signedEvent)}`,
                    'Content-Type': 'application/json',
                },
                body: challenge.payload || '',
            });
            const result = await verifyResponse.json();
            if (!verifyResponse.ok) throw new Error(result.error || 'Nostr authentication failed.');
            show('Authentication successful. Redirecting...', 'success');
            window.location.assign(result.redirect);
        } catch (error) {
            show(error instanceof Error ? error.message : 'Nostr authentication failed.', 'danger');
            button.disabled = false;
        }
    }

    if (!window.nostr || typeof window.nostr.signEvent !== 'function') {
        show('No NIP-07 extension was found. Install or unlock a Nostr browser extension, then reload this page.', 'warning');
        return;
    }
    show('Nostr extension detected. Continue when ready.', 'success');
    button.disabled = false;
    button.addEventListener('click', authenticate);
})();
