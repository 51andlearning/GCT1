// A deployment with no SIGNING_SECRET must refuse to sign rather than fall
// back to a value that anyone reading the repository already has.
delete process.env.SIGNING_SECRET;
process.env.GATE_CODE = 'TEST-GATE-CODE-9931';
delete process.env.RESEND_API_KEY;
delete process.env.SIGN_FROM_EMAIL;

const mw = (await import('./mw.mjs')).default;

const AUTH = '__Host-gct_access=gct-2026-a41f7c08b9d2e653';
const mk = (path, { method = 'GET', body } = {}) =>
  new Request('https://example.test' + path, {
    method,
    headers: { cookie: AUTH, ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {})
  });

let pass = 0, fail = 0;
async function t(name, fn) {
  try { await fn(); console.log('  ok   ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n       ' + e.message); fail++; }
}
const eq = (a, b, w) => { if (a !== b) throw new Error(`${w}: expected ${b}, got ${a}`); };

await t('config reports signing off', async () => {
  const j = await (await mw(mk('/api/config'))).json();
  eq(j.signingEnabled, false, 'signingEnabled');
  eq(j.otpEnabled, false, 'otpEnabled');
});
await t('signing is refused with 503', async () => {
  const body = {
    document: { hash: 'c'.repeat(64) },
    signatory: { name: 'A Person', position: 'CCO', company: 'GCT Group', email: 'a@b.co' },
    accepted: { services: [], totals: { onceOffUsd: 20000, monthlyMinimumUsd: 5000 } }
  };
  eq((await mw(mk('/api/sign', { method: 'POST', body }))).status, 503, 'status');
});
await t('requesting a one time code is refused too', async () => {
  eq((await mw(mk('/api/otp/request', { method: 'POST', body: { email: 'a@b.co' } }))).status, 503, 'status');
});
await t('the gate still works without a signing secret', async () => {
  const fd = new FormData(); fd.append('code', process.env.GATE_CODE);
  const r = await mw(new Request('https://example.test/unlock', {
    method: 'POST', headers: { 'x-vercel-forwarded-for': '203.0.113.44' }, body: fd
  }));
  eq(r.status, 303, 'status');
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
