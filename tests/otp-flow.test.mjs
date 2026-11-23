// Exercises the one time code path with email delivery configured.
process.env.RESEND_API_KEY = 'test-key';
process.env.SIGN_FROM_EMAIL = 'proposals@mvne.co.za';
process.env.SIGNING_SECRET = 'a-real-secret-for-the-test';
process.env.GATE_CODE = 'TEST-GATE-CODE-9931';

const sent = [];
globalThis.fetch = async (url, opts) => {
  sent.push({ url: String(url), body: JSON.parse(opts.body) });
  return new Response('{"id":"stub"}', { status: 200 });
};

const mw = (await import('./mw.mjs')).default;

const AUTH = '__Host-gct_access=gct-2026-a41f7c08b9d2e653';
const mk = (path, { method = 'GET', cookie = '', body } = {}) =>
  new Request('https://example.test' + path, {
    method, headers: { ...(cookie ? { cookie } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) },
    ...(body ? { body: JSON.stringify(body) } : {})
  });
// Vercel joins multiple Set-Cookie values with ", ". Pull one cookie back out.
const cookieFrom = (res, name) => {
  const raw = res.headers.get('set-cookie') || '';
  const m = raw.match(new RegExp(name + '=([^;,]*)'));
  return m ? `${name}=${m[1]}` : null;
};

let pass = 0, fail = 0;
async function t(name, fn) {
  try { await fn(); console.log('  ok   ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n       ' + e.message); fail++; }
}
const eq = (a, b, w) => { if (a !== b) throw new Error(`${w}: expected ${b}, got ${a}`); };

const EMAIL = 'adaeze.okonkwo@example.ng';
const HASH = 'b'.repeat(64);
const body = {
  document: { hash: HASH },
  signatory: { name: 'Adaeze Okonkwo', position: 'CCO', company: 'GCT Group', email: EMAIL },
  accepted: { services: [], totals: { onceOffUsd: 20000, monthlyMinimumUsd: 5000 } },
  signature: { mode: 'draw', image: 'data:image/png;base64,iVBORw0KGgo=' }
};

await t('config reports otp on when mail is configured', async () => {
  const j = await (await mw(mk('/api/config', { cookie: AUTH }))).json();
  eq(j.otpEnabled, true, 'otpEnabled');
  eq(j.signingEnabled, true, 'signingEnabled');
});

await t('signing is refused before the email is verified', async () => {
  const r = await mw(mk('/api/sign', { method: 'POST', cookie: AUTH, body }));
  eq(r.status, 403, 'status');
});

let chal, code;
await t('requesting a code emails a six digit number', async () => {
  const r = await mw(mk('/api/otp/request', { method: 'POST', cookie: AUTH, body: { email: EMAIL } }));
  const j = await r.json();
  eq(j.delivered, true, 'delivered');
  chal = cookieFrom(r, 'otp_chal');
  if (!chal) throw new Error('no challenge cookie');
  const mail = sent.at(-1);
  eq(mail.url, 'https://api.resend.com/emails', 'endpoint');
  eq(mail.body.to[0], EMAIL, 'recipient');
  const m = mail.body.html.match(/>(\d{6})</);
  if (!m) throw new Error('no code in the email body');
  code = m[1];
});

await t('a wrong code is rejected', async () => {
  const wrong = String((Number(code) + 1) % 1000000).padStart(6, '0');
  const r = await mw(mk('/api/otp/verify', { method: 'POST', cookie: AUTH + '; ' + chal, body: { code: wrong } }));
  eq(r.status, 400, 'status');
  eq((await r.json()).ok, false, 'ok');
});

let verified;
await t('the correct code verifies and issues a token', async () => {
  const r = await mw(mk('/api/otp/verify', { method: 'POST', cookie: AUTH + '; ' + chal, body: { code } }));
  eq(r.status, 200, 'status');
  eq((await r.json()).ok, true, 'ok');
  verified = cookieFrom(r, 'otp_ok');
  if (!verified) throw new Error('no otp_ok cookie');
});

await t('a tampered verification token is rejected', async () => {
  const bad = verified.slice(0, -4) + 'AAAA';
  const r = await mw(mk('/api/sign', { method: 'POST', cookie: AUTH + '; ' + bad, body }));
  eq(r.status, 403, 'status');
});

await t('signing with a mismatched address is rejected', async () => {
  const other = JSON.parse(JSON.stringify(body));
  other.signatory.email = 'someone.else@example.ng';
  const r = await mw(mk('/api/sign', { method: 'POST', cookie: AUTH + '; ' + verified, body: other }));
  eq(r.status, 403, 'status');
});

await t('signing succeeds once verified, and emails both parties', async () => {
  const r = await mw(mk('/api/sign', { method: 'POST', cookie: AUTH + '; ' + verified, body }));
  eq(r.status, 200, 'status');
  const j = await r.json();
  eq(j.delivered, true, 'delivered');
  eq(j.verification.method, 'email one time code', 'method');
  eq(j.verification.emailVerified, true, 'emailVerified');
  const mail = sent.at(-1);
  eq(mail.body.to.length, 2, 'recipient count');
  eq(mail.body.to[0], 'edwardw@mvne.co.za', 'notify address');
  eq(mail.body.to[1], EMAIL, 'signatory copy');
  eq(mail.body.attachments.length, 1, 'attachment count');
  if (!mail.body.attachments[0].filename.endsWith('.png')) throw new Error('attachment is not a png');
  if (mail.body.html.includes('<script')) throw new Error('unescaped markup in the email');
});

await t('an expired challenge is rejected', async () => {
  // Rebuild a challenge cookie with a timestamp in the past.
  const { createHmac } = await import('node:crypto');
  const exp = Math.floor(Date.now() / 1000) - 10;
  const mac = createHmac('sha256', process.env.SIGNING_SECRET)
    .update(`otp.${exp}.${EMAIL}.111111`).digest('hex');
  const tok = Buffer.from(`${exp}|${EMAIL}|${mac}`).toString('base64url');
  const r = await mw(mk('/api/otp/verify', { method: 'POST', cookie: AUTH + '; otp_chal=' + tok, body: { code: '111111' } }));
  eq(r.status, 400, 'status');
  if (!/expired/i.test((await r.json()).error)) throw new Error('expiry not reported');
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
