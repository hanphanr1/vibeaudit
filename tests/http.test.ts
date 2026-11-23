import { expect, test } from 'vitest';
import { guarded } from '../src/server/http';

const scan = guarded(async data => ({ data }));
const local = { host:'127.0.0.1:3000', origin:'http://127.0.0.1:3000', 'sec-fetch-site':'same-origin', 'content-type':'application/json' };
function request(headers: Record<string,string>, body = '{}') { return new Request('http://127.0.0.1:3000/api/scan',{method:'POST', headers, body}); }

test('rejects host, origin and fetch provenance mismatch while preserving no-store', async () => {
  for (const mismatch of [{host:'outside.invalid'}, {origin:'http://localhost:3000'}, {'sec-fetch-site':'cross-site'}]) {
    const response = await scan(request({...local,...mismatch} as Record<string,string>));
    expect(response.status).toBe(403);
    expect(response.headers.get('cache-control')).toBe('no-store');
  }
  expect((await scan(request(local))).status).toBe(200);
});

test('non-browser requests still require the exact origin even when Fetch Metadata is absent', async () => {
  const plain = {host:local.host,origin:local.origin,'content-type':'application/json'};
  expect((await scan(request(plain))).status).toBe(200);
  const response = await scan(request({host:local.host,'content-type':'application/json'}));
  expect(response.status).toBe(403);
  expect(response.headers.get('cache-control')).toBe('no-store');
});

test('bounds actual body size regardless of content-length', async () => {
  expect((await scan(request(local, JSON.stringify({ path:'a'.repeat(17000) })))).status).toBe(413);
});
