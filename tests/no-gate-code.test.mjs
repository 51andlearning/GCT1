// A deployment with no GATE_CODE must refuse everyone rather than fall open.
delete process.env.GATE_CODE;
delete process.env.SIGNING_SECRET;

const mw = (await import('./mw.mjs')).default;

let pass = 0, fail = 0;
async function t(name, fn) {
  try { await fn(); console.log('  ok   ' + name); pass++; }
  catch (e) { console.log('  FAIL ' + name + '\n       ' + e.message); fail++; }
}
const eq = (a, b, w) => { if (a !== b) throw new Error(`${w}: expected ${b}, got ${a}`); };

const post = code => {
  const fd = new FormData();
  fd.append('code', code);
  return new Request('https://example.test/unlock', {
    method: 'POST', headers: { 'x-vercel-forwarded-for': '203.0.113.60' }, body: fd
  });
};

await t('an empty submission is refused', async () => {
  const r = await mw(post(''));
  eq(r.headers.get('location'), '/gate?e=3', 'location');
  if (r.headers.get('set-cookie')) throw new Error('a cookie was issued with no code configured');
});
await t('any guess is refused, including a plausible one', async () => {
  for (const guess of ['GCT2026', 'password', 'admin', '    ']) {
    const r = await mw(post(guess));
    eq(r.headers.get('location'), '/gate?e=3', 'location for ' + JSON.stringify(guess));
    if (r.headers.get('set-cookie')) throw new Error('a cookie was issued for ' + guess);
  }
});
await t('pages still redirect to the gate rather than serving content', async () => {
  const r = await mw(new Request('https://example.test/mvno-light'));
  eq(r.status, 302, 'status');
  eq(r.headers.get('location'), '/gate', 'location');
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
