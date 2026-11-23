const allowedHost = /^(?:127\.0\.0\.1|localhost)(?::[1-9]\d{0,4})?$/;
const maxBody = 16 * 1024;

export class InputError extends Error {}

export function guarded(handle: (data: unknown) => Promise<unknown>) {
  return async (request: Request): Promise<Response> => {
    const respond = (data: unknown, status = 200) => Response.json(data, { status, headers: { 'Cache-Control': 'no-store' } });
    const host = request.headers.get('host') ?? '';
    const site = request.headers.get('sec-fetch-site');
    if (!allowedHost.test(host) || Number(host.split(':')[1] ?? '80') > 65535 ||
        request.headers.get('origin') !== 'http://' + host || (site !== 'same-origin' && site !== null)) {
      return respond({ error: 'Request is not from this local application.' }, 403);
    }
    if (request.method !== 'POST') return respond({ error: 'Method not allowed.' }, 405);
    const length = request.headers.get('content-length');
    if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBody)) return respond({ error: 'Request is too large.' }, 413);
    if (request.headers.get('content-type')?.split(';', 1)[0] !== 'application/json' || !request.body) return respond({ error: 'Expected a JSON body.' }, 415);
    const reader = request.body.getReader();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    let body = '', size = 0;
    let data: unknown;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maxBody) {
          await reader.cancel();
          return respond({ error: 'Request is too large.' }, 413);
        }
        body += decoder.decode(value, { stream: true });
      }
      data = JSON.parse(body + decoder.decode());
    } catch { return respond({ error: 'Malformed JSON request.' }, 400); }
    finally { reader.releaseLock(); }
    try { return respond(await handle(data)); }
    catch (error) {
      if (error instanceof InputError) return respond({ error: error.message }, 400);
      return respond({ error: 'Scan failed. Check the selected target and try again.' }, 500);
    }
  };
}
