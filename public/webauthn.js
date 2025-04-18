// WebAuthn Authentication Handler
class WebAuthnHandler {
    constructor() {
        this.baseUrl = '/api/webauthn';
    }

    async register(email) {
        try {
            // Start registration
            const startResponse = await fetch(`${this.baseUrl}/register/start`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email })
            });

            if (!startResponse.ok) {
                throw new Error('Failed to start registration');
            }

            const options = await startResponse.json();

            // Convert challenge to ArrayBuffer
            options.challenge = this.base64ToArrayBuffer(options.challenge);
            options.user.id = this.base64ToArrayBuffer(options.user.id);

            // Create credential
            const credential = await navigator.credentials.create({
                publicKey: options
            });

            // Convert credential to base64 for transmission
            const credentialData = {
                id: credential.id,
                rawId: this.arrayBufferToBase64(credential.rawId),
                type: credential.type,
                response: {
                    attestationObject: this.arrayBufferToBase64(credential.response.attestationObject),
                    clientDataJSON: this.arrayBufferToBase64(credential.response.clientDataJSON)
                }
            };

            // Complete registration
            const completeResponse = await fetch(`${this.baseUrl}/register/complete`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    credential: credentialData,
                    email
                })
            });

            if (!completeResponse.ok) {
                throw new Error('Failed to complete registration');
            }

            return await completeResponse.json();
        } catch (error) {
            console.error('WebAuthn registration error:', error);
            throw error;
        }
    }

    async authenticate(email) {
        try {
            // Start authentication
            const startResponse = await fetch(`${this.baseUrl}/authenticate/start`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email })
            });

            if (!startResponse.ok) {
                throw new Error('Failed to start authentication');
            }

            const options = await startResponse.json();

            // Convert challenge to ArrayBuffer
            options.challenge = this.base64ToArrayBuffer(options.challenge);
            options.allowCredentials = options.allowCredentials.map(cred => ({
                ...cred,
                id: this.base64ToArrayBuffer(cred.id)
            }));

            // Get credential
            const credential = await navigator.credentials.get({
                publicKey: options
            });

            // Convert credential to base64 for transmission
            const credentialData = {
                id: credential.id,
                rawId: this.arrayBufferToBase64(credential.rawId),
                type: credential.type,
                response: {
                    authenticatorData: this.arrayBufferToBase64(credential.response.authenticatorData),
                    clientDataJSON: this.arrayBufferToBase64(credential.response.clientDataJSON),
                    signature: this.arrayBufferToBase64(credential.response.signature),
                    userHandle: this.arrayBufferToBase64(credential.response.userHandle)
                }
            };

            // Complete authentication
            const completeResponse = await fetch(`${this.baseUrl}/authenticate/complete`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    credential: credentialData,
                    email
                })
            });

            if (!completeResponse.ok) {
                throw new Error('Failed to complete authentication');
            }

            return await completeResponse.json();
        } catch (error) {
            console.error('WebAuthn authentication error:', error);
            throw error;
        }
    }

    // Utility functions
    base64ToArrayBuffer(base64) {
        const binaryString = window.atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }
}

// Export the WebAuthnHandler class
window.WebAuthnHandler = WebAuthnHandler; 