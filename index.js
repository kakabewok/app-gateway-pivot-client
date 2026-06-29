const express = require('express');
const crypto = require('crypto');
const multer = require('multer');
const app = express();
const upload = multer();

// ================================================================
// CONFIG
// ================================================================
const PORT = process.env.PORT || 3000;
const EXPECTED_DOMAIN = process.env.EXPECTED_DOMAIN || 'sandbox';
const GATEWAY_PUBLIC_KEY = process.env.GATEWAY_PUBLIC_KEY;

// Validasi public key saat startup
if (!GATEWAY_PUBLIC_KEY) {
    console.error('FATAL: GATEWAY_PUBLIC_KEY environment variable tidak di-set!');
    process.exit(1);
}

try {
    crypto.createPublicKey(GATEWAY_PUBLIC_KEY);
    console.log('Public key loaded successfully');
} catch (e) {
    console.error('FATAL: Public key tidak valid:', e.message);
    process.exit(1);
}

// ================================================================
// HELPER: Verify RSA-SHA256 Signature
// ================================================================
function verifySignature(payload, signatureB64, publicKeyPem) {
    try {
        const keyObject = crypto.createPublicKey(publicKeyPem);
        console.log('[verifySignature] Public key loaded, type:', keyObject.asymmetricKeyType);

        const verify = crypto.createVerify('SHA256');
        verify.update(payload, 'utf8');
        return verify.verify(publicKeyPem, signatureB64, 'base64');
    } catch (err) {
        console.error('[verifySignature] Error:', err.message);
        console.error('[verifySignature] Public key preview:', publicKeyPem.substring(0, 80));
        return false;
    }
}

// ================================================================
// ENDPOINT: /router — format RPC dari ServiceProxy
// ================================================================
app.post('/router', upload.none(), (req, res) => {
    console.log('\n========================================');
    console.log('Incoming RPC webhook');
    console.log('========================================');

    // --- 1. Parse RPC body ---
    let rpcBody;
    try {
        rpcBody = JSON.parse(req.body.request);
    } catch (e) {
        console.error('[router] Failed to parse request:', e.message);
        console.error('[router] Raw body:', req.body);
        return res.status(200).json(false);
    }

    const parameters = rpcBody.parameters || [];
    const orderId = parameters[0];
    const amount = parameters[1];
    const domain = req.headers['domain'];
    const signature = req.headers['x-signature'];

    console.log('Service  :', rpcBody.service);
    console.log('Method   :', rpcBody.method);
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

    // --- 5. Proses notifikasi ---
    console.log(`[router] Order ${orderId} marked as PAID`);
    console.log('========================================\n');

    return res.status(200).json(true);
});

// ================================================================
// CATCH ALL
// ================================================================
app.use((req, res) => {
    console.log('404 - Not found:', req.method, req.path);
    return res.status(200).json(false);
});

// ================================================================
// START
// ================================================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Client app running on port ${PORT}`);
    console.log(`Expected domain: ${EXPECTED_DOMAIN}`);
    console.log(`Webhook endpoint: POST /router`);
});