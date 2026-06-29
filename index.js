const express = require('express');
const crypto = require('crypto');
const multer = require('multer');
const app = express();
const upload = multer();

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

// ================================================================
// HELPER: Verify RSA-SHA256 Signature
// ================================================================
function verifySignature(payload, signatureB64, publicKeyPem) {
    try {
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

// ================================================================
// ENDPOINT: /router — format RPC dari ServiceProxy
// ================================================================
app.post('/notify', upload.none(), (req, res) => {
    console.log('\n========================================');
    console.log('Incoming RPC webhook');
    console.log('========================================');
    console.log('Headers:', JSON.stringify(req.headers, null, 2));
    console.log('Body   :', req.body);

    // --- 1. Parse RPC body ---
    let rpcBody;
    try {
        rpcBody = JSON.parse(req.body.request);
    } catch (e) {
        console.error('[router] Failed to parse request:', e.message);
        return res.status(400).json(false);
    }

    const parameters = rpcBody.parameters || [];
    const orderId = parameters[0];
    const amount = parameters[1];

    console.log('Service :', rpcBody.service);
    console.log('Method  :', rpcBody.method);
    console.log('Order ID:', orderId);
    console.log('Amount  :', amount);

    // --- 2. Baca headers ---
    const domain = req.headers['domain'];
    const signature = req.headers['x-signature'];

    console.log('Domain   :', domain);
    console.log('Signature:', signature ?? '(tidak ada)');

    // --- 3. Validasi domain ---
    if (domain !== EXPECTED_DOMAIN) {
        console.warn('[router] Domain mismatch! Expected:', EXPECTED_DOMAIN, '| Got:', domain);
        return res.status(200).json(false);
    }

    // --- 4. Validasi X-Signature ---
    if (!signature) {
        console.warn('[router] X-Signature tidak ada!');
        return res.status(200).json(false);
    }

    const payload = `${orderId}|${amount}`;
    console.log('Payload to verify:', payload);

    const isValid = verifySignature(payload, signature, GATEWAY_PUBLIC_KEY);
    console.log('Signature valid  :', isValid);

    if (!isValid) {
        console.warn('[router] Signature INVALID - request ditolak');
        return res.status(200).json(false);
    }

    // --- 5. Proses notifikasi ---
    console.log(`[router] Order ${orderId} marked as PAID`);
    console.log('========================================\n');

    // ServiceProxy expect response boolean: true / false
    return res.status(200).json(true);
});

// ================================================================
// CATCH ALL — debug route tidak ketemu
// ================================================================
app.use((req, res) => {
    console.log('404 - Not found:', req.method, req.path);
    res.status(404).json(false);
});

// ================================================================
// START
// ================================================================
app.listen(PORT, () => {
    console.log(`Client app running on baseurl:${PORT}`);
});