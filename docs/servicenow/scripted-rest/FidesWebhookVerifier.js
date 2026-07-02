// FidesWebhookVerifier — Script Include (client_callable = false)
// -----------------------------------------------------------------------------
// Verifies the HMAC-SHA256 signature that Fides puts on every outbound webhook
// it delivers (pkg/webhooks). ServiceNow's built-in inbound webhook plumbing does
// NOT verify signatures, so a Scripted REST API resource must call this helper
// before trusting the payload.
//
// How Fides signs (must match exactly — see fides/pkg/webhooks/webhook.go, Sign):
//   signature = "sha256=" + hex( HMAC_SHA256(secret, timestamp + "." + rawBody) )
// delivered in these headers:
//   X-Fides-Signature   sha256=<hex>     (the value we recompute + compare)
//   X-Fides-Timestamp   <unix seconds>   (part of the signed payload; also used
//                                          to reject replays of stale deliveries)
//   X-Fides-Event-Id    <uuid>           (dedupe key; delivery is at-least-once)
//   X-Fides-Event-Type  <event type>
//
// The signed payload is the concatenation timestamp + "." + rawBody, where rawBody
// is the EXACT bytes Fides sent. Always hash request.body.dataString — never a
// re-serialized object, or the bytes (and therefore the HMAC) will differ.
//
// ServiceNow has no native hex-HMAC primitive, so we use GlideCertificateEncryption
// (which takes a base64 key and returns a base64 MAC) and convert the MAC to hex.
// -----------------------------------------------------------------------------
var FidesWebhookVerifier = Class.create();
FidesWebhookVerifier.prototype = {

    // Max age (seconds) a delivery's timestamp may be before we reject it as a
    // possible replay. Fides delivery is near-real-time; 300s is generous.
    MAX_SKEW_SECONDS: 300,

    initialize: function () {},

    /**
     * Verify a Fides webhook delivery.
     * @param {string} rawBody   request.body.dataString (exact bytes as received)
     * @param {string} sigHeader value of the X-Fides-Signature header ("sha256=<hex>")
     * @param {string} tsHeader  value of the X-Fides-Timestamp header (unix seconds)
     * @param {string} secret    the shared signing secret (plaintext)
     * @returns {{ok: boolean, reason: string}}
     */
    verify: function (rawBody, sigHeader, tsHeader, secret) {
        if (!secret) {
            return { ok: false, reason: 'no shared secret configured' };
        }
        if (!sigHeader || sigHeader.indexOf('sha256=') !== 0) {
            return { ok: false, reason: 'missing or malformed X-Fides-Signature' };
        }
        if (!tsHeader || !/^[0-9]+$/.test(tsHeader)) {
            return { ok: false, reason: 'missing or non-numeric X-Fides-Timestamp' };
        }

        // Replay guard: reject deliveries whose timestamp is too far from now.
        var nowSec = Math.floor(new GlideDateTime().getNumericValue() / 1000);
        var tsSec = parseInt(tsHeader, 10);
        if (Math.abs(nowSec - tsSec) > this.MAX_SKEW_SECONDS) {
            return { ok: false, reason: 'stale timestamp (possible replay)' };
        }

        var expectedHex = sigHeader.substring('sha256='.length);
        var signedPayload = tsHeader + '.' + (rawBody || '');
        var actualHex = this._hmacSha256Hex(secret, signedPayload);

        if (!this._constantTimeEquals(expectedHex.toLowerCase(), actualHex.toLowerCase())) {
            return { ok: false, reason: 'signature mismatch' };
        }
        return { ok: true, reason: 'ok' };
    },

    /**
     * HMAC-SHA256(secret, data) as a lowercase hex string.
     * GlideCertificateEncryption.generateMac wants a base64 key and returns a
     * base64 MAC, so we base64-encode the key and hex-encode the result.
     */
    _hmacSha256Hex: function (secret, data) {
        var keyB64 = GlideStringUtil.base64Encode(secret);
        var macB64 = new GlideCertificateEncryption().generateMac(keyB64, 'HmacSHA256', data);
        return this._base64ToHex(macB64);
    },

    _base64ToHex: function (b64) {
        var bytes = GlideStringUtil.base64DecodeAsBytes(b64); // Java byte[]
        var hex = '';
        for (var i = 0; i < bytes.length; i++) {
            var v = bytes[i] & 0xff;
            hex += (v < 16 ? '0' : '') + v.toString(16);
        }
        return hex;
    },

    // Length-independent, full-scan compare so a match takes the same work as a
    // near-miss (best effort in the scripting engine — do not early-return).
    _constantTimeEquals: function (a, b) {
        a = String(a);
        b = String(b);
        var diff = a.length ^ b.length;
        var max = Math.max(a.length, b.length);
        for (var i = 0; i < max; i++) {
            diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
        }
        return diff === 0;
    },

    type: 'FidesWebhookVerifier'
};
