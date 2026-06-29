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

function verifySignature(payload, signatureB64, publicKeyPem) {
    try {
        const verify = crypto.createVerify('SHA256');
        verify.update(payload, 'utf8');
        return verify.verify(publicKeyPem, signatureB64, 'base64');
    } catch (err) {
        console.error('[verifySignature] Error:', err.message);
        return false;
    }
}

app.post('/notify', upload.none(), (req, res) => {
    console.log('\n========================================');
    console.log('Incoming RPC webhook');

    // --- 1. Parse RPC body ---
    let rpcBody;
    try {
        rpcBody = JSON.parse(req.body.request);
    } catch (e) {
        console.error('[router] Failed to parse request:', e.message);
        return res.status(200).json(false);
    }

    const parameters = rpcBody.parameters || [];
    const orderId = parameters[0];
    const amount = parameters[1];
    const domain = req.headers['domain'];
    const signature = req.headers['x-signature'];

    console.log('Order ID :', orderId);
    console.log('Amount   :', amount);
    console.log('Domain   :', domain);
    console.log('Signature:', signature ?? '(tidak ada)');

    // --- 2. Validasi domain ---
    if (domain !== EXPECTED_DOMAIN) {
        console.warn('[router] Domain mismatch! Expected:', EXPECTED_DOMAIN, '| Got:', domain);
        return res.status(200).json(false);
    }

    // --- 3. Validasi X-Signature ---
    if (!signature) {
        console.warn('[router] X-Signature tidak ada!');
        return res.status(200).json(false);
    }

    // --- 4. Verify signature ---
    const payload = `${orderId}|${amount}`;
    console.log('Payload to verify:', payload);

    const isValid = verifySignature(payload, signature, GATEWAY_PUBLIC_KEY);
    console.log('Signature valid  :', isValid);

    if (!isValid) {
        console.warn('[router] Signature INVALID - request ditolak');
        return res.status(200).json(false);
    }

    // --- 5. Proses ---
    console.log(`[router] Order ${orderId} marked as PAID`);
    console.log('========================================\n');

    return res.status(200).json(true);
});

app.use((req, res) => {
    console.log('404:', req.method, req.path);
    return res.status(200).json(false);
});

app.listen(PORT, () => {
    console.log(`Client app running on ${PORT}`);
});