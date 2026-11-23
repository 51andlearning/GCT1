process.env.SIGNING_SECRET = 'test-signing-secret-for-the-suite';
// The live access code lives only in Vercel, so the suite sets its own.
process.env.GATE_CODE = 'TEST-GATE-CODE-9931';
const mw = (await import('./mw.mjs')).default;

const AUTH = '__Host-gct_access=gct-2026-a41f7c08b9d2e653';
const mk = (path, { method = 'GET', cookie = '', body, form, ip } = {}) => {
  const headers = { ...(cookie ? { cookie } : {}) };
  if (ip) headers['x-vercel-forwarded-for'] = ip;
  if (body) headers['Content-Type'] = 'application/json';
  const init = { method, headers };
  if (body) init.body = JSON.stringify(body);
  if (form) {
    const fd = new FormData();
    for (const [k, v] of Object.entries(form)) fd.append(k, v);
    init.body = fd;
  }
  return new Request('https://example.test' + path, init);
};
// Post the access code the way the gate form does.
const CODE = process.env.GATE_CODE;
const unlock = (code, ip = '203.0.113.9') =>
  mk('/unlock', { method: 'POST', form: { code }, ip });

const HASH = 'a'.repeat(64);
const goodBody = {
  document: { hash: HASH, title: 'GCT Group MVNO Light Proposal', version: '9 September 2026' },
  signatory: { name: 'Adaeze Okonkwo', position: 'CCO', company: 'GCT Group', email: 'a.okonkwo@example.ng', mobile: '+234 802 555 0111' },
  accepted: { services: [{ id: 'pwa', name: 'MVNO PWA platform' }], totals: { onceOffUsd: 32507, monthlyMinimumUsd: 9250 } },
  signature: { mode: 'type', image: 'data:image/png;base64,iVBORw0KGgo=' }
};

let pass = 0, fail = 0;
async function t(name, fn) {
  try { await fn(); console.log('  ok   ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n       ' + e.message); fail++; }
}
const eq = (a, b, what) => { if (a !== b) throw new Error(`${what}: expected ${b}, got ${a}`); };

console.log('gate');
await t('unauthenticated page redirects to /gate', async () => {
  const r = await mw(mk('/mvno-light'));
  eq(r.status, 302, 'status'); eq(r.headers.get('location'), '/gate', 'location');
});
await t('gate page itself is public', async () => {
  eq((await mw(mk('/gate'))).headers.get('x-mw'), 'next', 'passthrough');
});
await t('og image is public for link previews', async () => {
  eq((await mw(mk('/og-image.png'))).headers.get('x-mw'), 'next', 'passthrough');
});
await t('correct code sets the cookie', async () => {
  const r = await mw(unlock(CODE));
  eq(r.status, 303, 'status');
  const c = r.headers.get('set-cookie') || '';
  if (!/__Host-gct_access=/.test(c)) throw new Error('no auth cookie');
  for (const flag of ['HttpOnly', 'Secure', 'Path=/', 'SameSite=Lax']) {
    if (!c.includes(flag)) throw new Error('cookie missing ' + flag);
  }
});
await t('the code is accepted in any case', async () => {
  eq((await mw(unlock(CODE.toLowerCase(), '203.0.113.10'))).status, 303, 'lower case');
  eq((await mw(unlock('  ' + CODE.toLowerCase().replace('t','T') + ' ', '203.0.113.11'))).status, 303, 'padded and mixed');
});
await t('wrong code bounces back to the gate', async () => {
  eq((await mw(unlock('nope', '203.0.113.12'))).headers.get('location'), '/gate?e=1', 'location');
});
await t('the code is never accepted from the query string', async () => {
  const r = await mw(mk('/unlock?pin=' + CODE));
  eq(r.headers.get('location'), '/gate', 'GET is sent back to the gate');
  if (r.headers.get('set-cookie')) throw new Error('a GET must never set the cookie');
});
await t('an empty code is refused', async () => {
  eq((await mw(unlock('', '203.0.113.13'))).headers.get('location'), '/gate?e=1', 'location');
});
await t('repeated wrong codes from one address are rate limited', async () => {
  const ip = '198.51.100.7';
  let limited = false;
  for (let i = 0; i < 9; i++) {
    const r = await mw(unlock('wrong' + i, ip));
    if (r.headers.get('location') === '/gate?e=2') { limited = true; break; }
  }
  if (!limited) throw new Error('never rate limited after nine attempts');
  // A locked window refuses the correct code too, otherwise it is theatre.
  const r = await mw(unlock(CODE, ip));
  eq(r.headers.get('location'), '/gate?e=2', 'correct code during lockout');
});
await t('the limit is per address, so one attacker cannot lock everyone out', async () => {
  eq((await mw(unlock(CODE, '198.51.100.200'))).status, 303, 'a different address still works');
});
await t('authenticated page passes through', async () => {
  eq((await mw(mk('/mvno-light', { cookie: AUTH }))).headers.get('x-mw'), 'next', 'passthrough');
});

console.log('signing api');
await t('api requires authentication', async () => {
  eq((await mw(mk('/api/config'))).status, 401, 'status');
});
await t('config reports otp off when mail is unconfigured', async () => {
  const j = await (await mw(mk('/api/config', { cookie: AUTH }))).json();
  eq(j.otpEnabled, false, 'otpEnabled');
  eq(j.signingEnabled, true, 'signingEnabled with a secret');
});
await t('sign rejects GET', async () => {
  eq((await mw(mk('/api/sign', { cookie: AUTH }))).status, 405, 'status');
});
await t('sign rejects a bad hash', async () => {
  const b = JSON.parse(JSON.stringify(goodBody)); b.document.hash = 'short';
  eq((await mw(mk('/api/sign', { method: 'POST', cookie: AUTH, body: b }))).status, 400, 'status');
});
await t('sign rejects a missing name', async () => {
  const b = JSON.parse(JSON.stringify(goodBody)); b.signatory.name = '';
  eq((await mw(mk('/api/sign', { method: 'POST', cookie: AUTH, body: b }))).status, 400, 'status');
});
await t('sign rejects a bad email', async () => {
  const b = JSON.parse(JSON.stringify(goodBody)); b.signatory.email = 'not-an-email';
  eq((await mw(mk('/api/sign', { method: 'POST', cookie: AUTH, body: b }))).status, 400, 'status');
});
let signed;
await t('sign returns a reference and a record signature', async () => {
  const r = await mw(mk('/api/sign', { method: 'POST', cookie: AUTH, body: goodBody }));
  eq(r.status, 200, 'status');
  signed = await r.json();
  if (!/^GCT-ML-\d{8}-[0-9A-F]{6}$/.test(signed.reference)) throw new Error('bad reference ' + signed.reference);
  if (!/^[0-9a-f]{64}$/.test(signed.recordSignature)) throw new Error('bad record signature');
  eq(signed.delivered, false, 'delivered without mail config');
  eq(signed.verification.method, 'site access code and signatory confirmation', 'method');
});
await t('the record signature is reproducible and tamper evident', async () => {
  const again = await (await mw(mk('/api/sign', { method: 'POST', cookie: AUTH, body: goodBody }))).json();
  // A different signedAt means a different signature, so recompute over the returned fields.
  const { createHmac } = await import('node:crypto');
  const SECRET = process.env.SIGNING_SECRET;
  const canonical = ['gct-mvno-light-v1', HASH, 'Adaeze Okonkwo', 'CCO', 'GCT Group',
    'a.okonkwo@example.ng', signed.signedAt, 'site access code and signatory confirmation',
    'pwa', '32507', '9250'].join('|');
  const expect = createHmac('sha256', SECRET).update(canonical).digest('hex');
  eq(signed.recordSignature, expect, 'recomputed signature');
  if (again.recordSignature === signed.recordSignature && again.signedAt !== signed.signedAt)
    throw new Error('signature did not change with the timestamp');
});
await t('otp request is refused when mail is unconfigured', async () => {
  const j = await (await mw(mk('/api/otp/request', { method: 'POST', cookie: AUTH, body: { email: 'a@b.co' } }))).json();
  eq(j.delivered, false, 'delivered');
});
await t('otp verify without a challenge fails', async () => {
  const r = await mw(mk('/api/otp/verify', { method: 'POST', cookie: AUTH, body: { code: '123456' } }));
  eq(r.status, 400, 'status');
});
await t('unknown api endpoint is a 404', async () => {
  eq((await mw(mk('/api/nope', { method: 'POST', cookie: AUTH, body: {} }))).status, 404, 'status');
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
