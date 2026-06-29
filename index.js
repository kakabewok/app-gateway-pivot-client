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

console.log('ENV PORT value:', process.env.PORT);
console.log('Binding to port:', PORT);

// Validate public key on startup
if (!GATEWAY_PUBLIC_KEY) {
    console.error('FATAL: GATEWAY_PUBLIC_KEY environment variable is not set!');
    process.exit(1);
}

try {
    crypto.createPublicKey(GATEWAY_PUBLIC_KEY);
    console.log('Public key loaded successfully');
} catch (e) {
    console.error('FATAL: Public key is invalid:', e.message);
    process.exit(1);
}

// ================================================================
// HELPER: Build RPC-style response (matches ServiceProxy format)
// ================================================================
function rpcResponse(res, data) {
    return res.status(200).json({ data, message: null });
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
        return false;
    }
}

// ================================================================
// ENDPOINT: /notify — RPC format from ServiceProxy
// ================================================================
app.post('/notify', upload.none(), (req, res) => {
    console.log('\n========================================');
    console.log('Incoming RPC webhook');
    console.log('========================================');

    // --- 1. Parse RPC body ---
    let rpcBody;
    try {
        rpcBody = JSON.parse(req.body.request);
    } catch (e) {
        console.error('[notify] Failed to parse request:', e.message);
        console.error('[notify] Raw body:', req.body);
        return rpcResponse(res, false);
    }

    const parameters = rpcBody.parameters || [];
    const orderId = parameters[0];
    const amount = parameters[1];
    const domain = req.headers['domain'];
    const signature = req.headers['X-Signature'];

    console.log('Service  :', rpcBody.service);
    console.log('Method   :', rpcBody.method);
    console.log('Order ID :', orderId);
    console.log('Amount   :', amount);
    console.log('Domain   :', domain);
    console.log('Signature:', signature ?? '(not present)');

    // --- 2. Validate domain ---
    if (domain !== EXPECTED_DOMAIN) {
        console.warn('[notify] Domain mismatch! Expected:', EXPECTED_DOMAIN, '| Got:', domain);
        return rpcResponse(res, false);
    }

    // --- 3. Validate X-Signature header ---
    if (!signature) {
        console.warn('[notify] X-Signature header is missing!');
        return rpcResponse(res, false);
    }

    // --- 4. Verify signature ---
    // Normalize amount format to always include decimal (consistent with Java Double)
    const amountStr = Number.isInteger(amount)
        ? amount.toFixed(1)   // e.g. 22000 -> "22000.0"
        : String(amount);     // e.g. 22000.5 -> "22000.5"

    const payload = `${orderId}|${amountStr}`;
    console.log('Payload to verify:', payload);

    const isValid = verifySignature(payload, signature, GATEWAY_PUBLIC_KEY);
    console.log('Signature valid  :', isValid);

    if (!isValid) {
        console.warn('[router] Signature is INVALID - request rejected');
        return rpcResponse(res, false);
    }

    // --- 5. Process notification ---
    // TODO: update your order status here (e.g. Order.updateStatus(orderId, 'PAID'))
    console.log(`[notify] Order ${orderId} successfully marked as PAID`);
    console.log('========================================\n');

    return rpcResponse(res, true);
});

// ================================================================
// CATCH ALL — handle unknown routes
// ================================================================
app.use((req, res) => {
    console.log('404 - Route not found:', req.method, req.path);
    return rpcResponse(res, false);
});

// ================================================================
// START SERVER
// ================================================================
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Client app running on port ${PORT}`);
    console.log(`Expected domain  : ${EXPECTED_DOMAIN}`);
    console.log(`Webhook endpoint : POST /notify`);
});