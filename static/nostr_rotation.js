(function() {
    const button = document.getElementById('rotateNostrKey');
    if (!button) return;
    button.addEventListener('click', async function() {
        if (!window.nostr || typeof window.nostr.signEvent !== 'function') {
            window.alert('No NIP-07 extension was found.');
            return;
        }
        if (!window.confirm('Sign with the new Nostr key? You will be logged out after rotation.')) return;
        try {
            async function signStep(action, endpoint) {
                const challengeResponse = await window.csrfFetch('/api/auth/challenge', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action }),
                });
                const challenge = await window.readJsonResponse(
                    challengeResponse,
                    'Could not create an authentication challenge.'
                );
                const event = await window.nostr.signEvent(challenge.event);
                const token = btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(event))));
                const response = await window.csrfFetch(endpoint, {
                    method: 'POST', headers: { Authorization: `Nostr ${token}`, 'Content-Type': 'application/json' }, body: '',
                });
                const result = await window.readJsonResponse(
                    response,
                    'Nostr key rotation failed.'
                );
                return result;
            }
            await signStep('rotate-current', '/api/auth/rotate-current');
            window.alert('Switch your extension to the new Nostr key, then approve the next request.');
            const result = await signStep('rotate-key', '/api/auth/rotate-key');
            window.location.assign(result.redirect);
        } catch (error) {
            window.alert(error instanceof Error ? error.message : 'Nostr key rotation failed.');
        }
    });
})();
