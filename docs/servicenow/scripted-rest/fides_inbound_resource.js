// Scripted REST API resource operation script
// -----------------------------------------------------------------------------
// API:      "Fides Inbound"           (api_id: x_fides_inbound, adjust to your scope)
// Resource: POST /api/<scope>/fides_inbound/events
// Full path once published:
//   https://<instance>.service-now.com/api/<scope>/fides_inbound/events
//
// Point a Fides tenant webhook at this URL:
//   POST /api/v1/tenant/webhooks  { "url": "<the URL above>", "secret_path": "SNOW_WEBHOOK_SECRET", ... }
// Fides then signs each delivery with X-Fides-Signature (see FidesWebhookVerifier).
//
// Security note: mark the resource "Requires authentication" and additionally
// verify the HMAC below. The HMAC proves the body came from Fides and was not
// tampered with; ACLs/basic-auth alone cannot prove payload integrity.
// -----------------------------------------------------------------------------
(function process(request, response) {

    // Resolve the shared secret. Store it OUTSIDE the script — see the doc for
    // options. Simplest: a system property (encrypted). Best: a Connection &
    // Credential alias / Credentials record read via sn_cc.
    var secret = gs.getProperty('x_fides.webhook.shared_secret', '');

    var rawBody = request.body ? request.body.dataString : '';
    var sig = request.getHeader('x-fides-signature');
    var ts = request.getHeader('x-fides-timestamp');
    var eventId = request.getHeader('x-fides-event-id');
    var eventType = request.getHeader('x-fides-event-type');

    var verdict = new FidesWebhookVerifier().verify(rawBody, sig, ts, secret);
    if (!verdict.ok) {
        gs.warn('[Fides] rejected webhook ' + eventId + ': ' + verdict.reason);
        response.setStatus(401);
        response.setBody({ error: 'signature verification failed', reason: verdict.reason });
        return;
    }

    // Signature is valid — the body is authentic. Parse and act on it.
    // Delivery is at-least-once, so dedupe on X-Fides-Event-Id before side effects.
    var payload = {};
    try {
        payload = JSON.parse(rawBody);
    } catch (e) {
        response.setStatus(400);
        response.setBody({ error: 'invalid json body' });
        return;
    }

    // Example: fan out on the Fides event type. The envelope is
    //   { id, type, org_id, payload, sent_at }
    // See docs/servicenow-integration.md for the event catalogue.
    switch (eventType) {
        case 'compliance.evaluated':
        case 'servicenow.change_gate':
            // e.g. update a change_request work note, raise/clear a flag, etc.
            gs.info('[Fides] verified ' + eventType + ' event ' + eventId);
            break;
        default:
            gs.info('[Fides] verified (unhandled) ' + eventType + ' event ' + eventId);
    }

    response.setStatus(200);
    response.setBody({ status: 'accepted', event_id: eventId });
})(request, response);
