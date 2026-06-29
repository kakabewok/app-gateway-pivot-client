const express = require('express');
const crypto = require('crypto');
const app = express();

// CONFIG
const PORT = 3000;
const EXPECTED_DOMAIN = 'sandbox';

const GATEWAY_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2UBjF4SJI/s3mDJoSnHr
ZufAwHXsVEQJMJlIzIsidvm0xSstXNIkfoJScAmPC0S+KF2vs/EKZjcbIttzBNpx
w7jzlZeV5p6PxAFeKmssue72YA9wY1mGW0/2YCSgUDVLucw/JbqAlJTkHfVpFAIB
ABCFw72HFnXNm/cVMzfqfOrS/VaEqiVEEs5Jwqx/C3FiETRdu7wxhdiIhc+XrXA4
2/snli7Wf3CB4SINORT/SlZkVnlwpS0ZuBqipNEN5Pf6DU6Kw7yEAsfygT+ZBMh/
mHoFlhApFYrBdOF4Vtv+ekgNvz0g5QPrCuH9pKQaY/jSnEGwPVQI7rfl5urgKBkw
2wIDAQAB-----END PUBLIC KEY-----`;

// MIDDLEWARE
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// HELPER: Verify RSA-SHA256 Signature
function verifySignature(payload, signatureB64, publicKeyPem) {
    try {
        // Handle URL-safe Base64 (- -> +, _ -> /)
        const normalized = signatureB64
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);

        const verify = crypto.createVerify('SHA256');
        verify.update(payload, 'utf8');
        return verify.verify(publicKeyPem, padded, 'base64');
    } catch (err) {
        console.error('[verifySignature] Error:', err.message);
        return false;
    }
}

// ENDPOINT: Receive Webhook from Gateway
app.post('/notify', (req, res) => {
    console.log('\n========================================');
    console.log('Incoming webhook received');
    console.log('========================================');

    // --- 1. Parse RPC request from form-data ---
    let rpcBody;
    try {
        rpcBody = JSON.parse(req.body.request);
    } catch (e) {
        console.error('[notify] Failed to parse request body:', e.message);
        return res.status(400).json({ success: false, message: 'Invalid request format' });
    }

    const parameters = rpcBody.parameters || [];
    const orderId = parameters[0];
    const amount = parameters[1];

    console.log('Service   :', rpcBody.service);
    console.log('Method    :', rpcBody.method);
    console.log('Order ID  :', orderId);
    console.log('Amount    :', amount);

    const domain = req.headers['domain'];
    const signature = req.headers['X-Signature'];

    console.log('Domain    :', domain);
    console.log('Signature :', signature ?? '(Not Found)');

    // --- 3. Domain Validation ---
    if (domain !== EXPECTED_DOMAIN) {
        console.warn('[notify] Domain mismatch! Expected:', EXPECTED_DOMAIN, '| Got:', domain);
        return res.status(200).json({ success: false, message: 'Domain mismatch' });
    }

    // --- 4. X-Signature Validation ---
    if (!signature) {
        console.warn('[notify] X-Signature header does not exist!');
        return res.status(200).json({ success: false, message: 'Missing X-Signature' });
    }

    const payload = `${orderId}|${amount}`;
    console.log('Payload to verify:', payload);

    const isValid = verifySignature(payload, signature, GATEWAY_PUBLIC_KEY);
    console.log('Signature valid  :', isValid);

    if (!isValid) {
        console.warn('[notify] Signature INVALID - request rejected');
        return res.status(200).json({ success: false, message: 'Invalid signature' });
    }

    console.log('[notify] Signature VALID - processing notification...');

    console.log(`[notify] Order ${orderId} successfully updated to PAID`);
    console.log('========================================\n');

    return res.status(200).json({ success: true });
});

// START SERVER
app.listen(PORT, () => {
    console.log(`Client app running on http://localhost:${PORT}`);
    console.log(`Webhook endpoint: POST http://localhost:${PORT}/notify`);
});