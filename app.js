import { ClientRequestInterceptor } from '@mswjs/interceptors/ClientRequest'

function checkPII(str) {
    const VALIDATOR_REGEXPS = Object.seal({
        EMAIL: /([a-z0-9_\-.+]+)@\w+(\.\w+)*/,
        PHONE: /(\(?\+?[0-9]{1,2}\)?[-. ]?)?(\(?[0-9]{3}\)?|[0-9]{3})[-. ]?([0-9]{3}[-. ]?[0-9]{4}|\b[A-Z0-9]{7}\b)/,
        PROPERTY_UNIT_NUMBER: /(apt|bldg|dept|fl|hngr|lot|pier|rm|ste|slip|trlr|unit|#)\s*\.?#?\s*[0-9]+[a-z0-9-]*\b/i,
        PROPERTY_STREET_ADDRESS: /\d+(\s+[nsew]\.?)?(\s+\w+){1,}\s+(?:st(?:\.|reet)?|dr(?:\.|ive)?|pl(?:\.|ace)?|ave(?:\.|nue)?|rd|road|lane|boulevard|blvd|loop|way|circle|cir|court|ct|plaza|square|run|parkway|point|pike|square|driveway|trace|park|terrace)(\s|[^a-z]|$)/,
        SSN: /\b\d{3}[ -.]\d{2}[ -.]\d{4}\b/
    });

    const matched = [];
    for (const rx in VALIDATOR_REGEXPS) {
        if (str.match(VALIDATOR_REGEXPS[rx])) {
            matched.push(rx);
        }
    }

    return matched;
}

export async function trace(key = '', callback) {
    const interceptor = new ClientRequestInterceptor()

    interceptor.apply()

    const requests = {};

    interceptor.on('request', async ({ request, requestId }) => {
        const reader = await request.arrayBuffer();
        var enc = new TextDecoder('utf-8');
        const requestBody = enc.decode(reader);

        const url = new URL(request.url);
        const pii = checkPII(requestBody);
        const result = {
            requestId,
            timestamp: new Date().getTime(),
            method: request.method,
            hostname: url.hostname,
            url: request.url,
            requestPii: pii,
        };

        requests[requestId] = result;
    })

    interceptor.on(
        'response',
        async ({ response, requestId }) => {
            const responseBuf = await response.arrayBuffer();
            var enc = new TextDecoder('utf-8');
            const responseBody = enc.decode(responseBuf);

            const pii = checkPII(responseBody);

            requests[requestId].responsePii = pii;
            callback(requests[requestId]);
        }
    );
}