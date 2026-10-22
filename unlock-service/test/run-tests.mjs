// End-to-end tests against `wrangler dev --local` (Miniflare + local D1).
// node test/run-tests.mjs
import { spawn, execSync } from 'node:child_process';
import { writeFileSync, rmSync } from 'node:fs';
import { webcrypto as crypto, randomBytes } from 'node:crypto';
import * as lib from '../src/lib.js';

const PORT = 8799, BASE = `http://127.0.0.1:${PORT}`, TEAM = 'unite-test.cloudflareaccess.com', AUD = 'test-aud-123';
const EXT = 'chrome-extension://ekiejhjpombecjiogemccfefgcpabmak';
let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('PASS', m); } else { fail++; console.log('FAIL', m); } };

// ---- pure lib tests
ok(lib.normalizeOrigin('https://App.TheCosecHouse.co.uk/firstorder.php?x=1') === 'https://app.thecosechouse.co.uk', 'origin normalise url');
ok(lib.normalizeOrigin('app.thecosechouse.co.uk') === 'https://app.thecosechouse.co.uk', 'origin bare host -> https');
ok(lib.normalizeOrigin('https://a.com:443') === 'https://a.com' && lib.normalizeOrigin('https://a.com:8443') === 'https://a.com:8443', 'origin ports');
ok(lib.normalizeOrigin('https://user@evil.com') === null && lib.normalizeOrigin('javascript:alert(1)') === null, 'origin rejects userinfo/js');
ok(lib.normalizeTicket('tk-15345') === 'TK-15345' && lib.normalizeTicket('15345') === 'TK-15345' && lib.normalizeTicket('') === null && lib.normalizeTicket('hello') === null, 'ticket normalise');
const g = lib.generateCode(); ok(/^[0-9A-Z]{5}-[0-9A-Z]{5}$/.test(g) && lib.isWellFormedCode(lib.normalizeCode(g)), 'code format ' + g);
ok(lib.normalizeCode('abcde-fghio') === 'ABCDEFGH10', 'crockford aliases');
ok(lib.emailAllowed('zack@unite-networks.com', 'unite-networks.com') && !lib.emailAllowed('x@evil-unite-networks.com', 'unite-networks.com') && !lib.emailAllowed('x@unite-networks.com.evil.io', 'unite-networks.com'), 'issuer domain exact');

// ---- Access JWT test key
const kp = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
const pub = { ...(await crypto.subtle.exportKey('jwk', kp.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
const b64u = (b) => Buffer.from(b).toString('base64url');
async function jwt(payload, { kid = 'k1', key = kp.privateKey } = {}) {
  const h = b64u(JSON.stringify({ alg: 'RS256', kid, typ: 'JWT' })), p = b64u(JSON.stringify(payload));
  const s = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(h + '.' + p));
  return `${h}.${p}.${b64u(new Uint8Array(s))}`;
}
const now = () => Math.floor(Date.now() / 1000);
const goodJwt = (email = 'zack@unite-networks.com') => jwt({ aud: [AUD], iss: `https://${TEAM}`, email, exp: now() + 600, iat: now() });

writeFileSync('.dev.vars', [
  'ENVIRONMENT=test', `ACCESS_TEAM_DOMAIN=${TEAM}`, `ACCESS_AUD=${AUD}`,
  `ACCESS_TEST_JWKS=${JSON.stringify({ keys: [pub] })}`, `UNLOCK_PEPPER=${randomBytes(32).toString('hex')}`, 'CODE_TTL_MINUTES=15',
].join('\n'));
rmSync('.wrangler/state', { recursive: true, force: true });
execSync('npx wrangler d1 migrations apply urlcheck-unlock-staging --local', { stdio: 'pipe' });
const dev = spawn('npx', ['wrangler', 'dev', '--local', '--port', String(PORT), '--ip', '127.0.0.1'], { stdio: 'pipe', detached: true });
let log = ''; dev.stdout.on('data', (d) => (log += d)); dev.stderr.on('data', (d) => (log += d));
for (let i = 0; i < 60; i++) { try { const r = await fetch(BASE + '/v1/health'); if (r.ok) break; } catch {} await new Promise((r) => setTimeout(r, 1000)); }

const admin = async (path, { method = 'GET', body, token, csrf = true, origin } = {}) => {
  const h = { 'content-type': 'application/json' };
  if (token !== null) h['cf-access-jwt-assertion'] = token ?? (await goodJwt());
  if (csrf) h['x-urlcheck-admin'] = '1';
  if (origin) h['origin'] = origin;
  const r = await fetch(BASE + path, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, j: await r.json().catch(() => ({})) };
};
const redeem = async (body, origin = EXT, ip) => {
  const h = { 'content-type': 'application/json' }; if (origin) h.origin = origin; if (ip) h['cf-connecting-ip'] = ip;
  const r = await fetch(BASE + '/v1/unlock/redeem', { method: 'POST', headers: h, body: JSON.stringify(body) });
  return { status: r.status, j: await r.json() };
};

try {
  ok((await fetch(BASE + '/v1/health')).ok, 'health');
  // auth
  ok((await admin('/admin/api/codes', { token: null })).status === 401, 'admin: no JWT -> 401');
  ok((await admin('/admin/api/codes', { token: await goodJwt('eve@gmail.com') })).status === 403, 'admin: non-Unite email -> 403');
  ok((await admin('/admin/api/codes', { token: await jwt({ aud: ['other'], iss: `https://${TEAM}`, email: 'zack@unite-networks.com', exp: now() + 600 }) })).status === 401, 'admin: wrong aud -> 401');
  ok((await admin('/admin/api/codes', { token: await jwt({ aud: [AUD], iss: `https://${TEAM}`, email: 'zack@unite-networks.com', exp: now() - 10 }) })).status === 401, 'admin: expired JWT -> 401');
  const other = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  ok((await admin('/admin/api/codes', { token: await jwt({ aud: [AUD], iss: `https://${TEAM}`, email: 'zack@unite-networks.com', exp: now() + 600 }, { key: other.privateKey }) })).status === 401, 'admin: forged signature -> 401');
  const page = await fetch(BASE + '/admin', { headers: { 'cf-access-jwt-assertion': await goodJwt() } });
  ok(page.ok && (await page.text()).includes('Generate code'), 'admin page served with valid JWT');

  // issue
  ok((await admin('/admin/api/codes', { method: 'POST', body: { url: 'https://app.thecosechouse.co.uk/' } })).status === 400, 'issue: ticket mandatory');
  ok((await admin('/admin/api/codes', { method: 'POST', body: { ticket: 'TK-15345' } })).status === 400, 'issue: origin mandatory');
  ok((await admin('/admin/api/codes', { method: 'POST', csrf: false, body: { ticket: 'TK-15345', url: 'https://a.com' } })).status === 400, 'issue: CSRF header required');
  ok((await admin('/admin/api/codes', { method: 'POST', origin: 'https://evil.com', body: { ticket: 'TK-15345', url: 'https://a.com' } })).status === 400, 'issue: cross-origin POST refused');
  const iss = await admin('/admin/api/codes', { method: 'POST', body: { ticket: 'tk-15345', url: 'https://app.thecosechouse.co.uk/firstorder.php?_hsenc=x', reason: 'FirstOrder link', grantTtlSeconds: 14400 } });
  ok(iss.j.ok && iss.j.ticket === 'TK-15345' && iss.j.origin === 'https://app.thecosechouse.co.uk' && /^[0-9A-Z]{5}-[0-9A-Z]{5}$/.test(iss.j.code), 'issue: ok ' + iss.j.code);
  ok(Math.abs(iss.j.expiresAt - (Date.now() + 15 * 60 * 1000)) < 60000, 'issue: 15 min redeem window');
  const list = await admin('/admin/api/codes');
  ok(list.j.codes.length === 1 && !('code' in list.j.codes[0]) && !('code_hash' in list.j.codes[0]) && list.j.codes[0].status === 'active', 'list: no plaintext/hash, active');

  // redeem
  ok((await redeem({ code: iss.j.code, origin: 'https://app.thecosechouse.co.uk' }, 'https://evil.com')).status === 403, 'redeem: web-page Origin refused');
  const wrong = await redeem({ code: iss.j.code, origin: 'https://evil.example', deviceId: 'dev-A' });
  ok(!wrong.j.ok && wrong.j.result === 'wrong_origin', 'redeem: wrong origin rejected, not consumed');
  const r1 = await redeem({ code: iss.j.code.toLowerCase(), url: 'https://app.thecosechouse.co.uk/firstorder.php?utm=1', deviceId: 'dev-A', deviceLabel: 'L-5CD2419P4Y', extVersion: '1.4.0' });
  ok(r1.j.ok && r1.j.result === 'success' && r1.j.unlockTtlSeconds === 14400 && r1.j.ticket === 'TK-15345', 'redeem: success (case-insensitive, url accepted)');
  const r2 = await redeem({ code: iss.j.code, origin: 'https://app.thecosechouse.co.uk', deviceId: 'dev-B' });
  ok(!r2.j.ok && r2.j.result === 'used', 'redeem: second device refused (fleet-wide single use)');
  // concurrency: 10 parallel redeems of a fresh code -> exactly 1 success
  const c2 = await admin('/admin/api/codes', { method: 'POST', body: { ticket: 'TK-1001', url: 'https://race.example' } });
  const rs = await Promise.all([...Array(10)].map((_, i) => redeem({ code: c2.j.code, origin: 'https://race.example', deviceId: 'race-' + i })));
  ok(rs.filter((x) => x.j.ok).length === 1, 'redeem: parallel race -> exactly one success');
  // revoke
  const c3 = await admin('/admin/api/codes', { method: 'POST', body: { ticket: 'TK-1002', url: 'https://rev.example' } });
  const rv = await admin(`/admin/api/codes/${c3.j.codeId}/revoke`, { method: 'POST', body: {} });
  ok(rv.j.ok, 'revoke ok');
  const r3 = await redeem({ code: c3.j.code, origin: 'https://rev.example', deviceId: 'dev-C' });
  ok(!r3.j.ok && r3.j.result === 'revoked', 'redeem: revoked code refused');
  // expiry: issue with 15-min window, then simulate by direct DB edit
  const c4 = await admin('/admin/api/codes', { method: 'POST', body: { ticket: 'TK-1003', url: 'https://exp.example' } });
  execSync(`npx wrangler d1 execute urlcheck-unlock-staging --local --command "UPDATE unlock_codes SET expires_at = 1 WHERE code_id = '${c4.j.codeId}'"`, { stdio: 'pipe' });
  const r4 = await redeem({ code: c4.j.code, origin: 'https://exp.example', deviceId: 'dev-D' });
  ok(!r4.j.ok && r4.j.result === 'expired', 'redeem: expired code refused');
  // garbage + rate limit per device
  ok((await redeem({ code: 'nope', origin: 'https://x.example', deviceId: 'dev-E' })).j.result === 'invalid', 'redeem: malformed code invalid');
  let last; for (let i = 0; i < 6; i++) last = await redeem({ code: lib.generateCode(), origin: 'https://x.example', deviceId: 'dev-RL', }, EXT, '10.9.9.9');
  ok(last.status === 429 && last.j.result === 'rate_limited', 'redeem: device rate-limited after 5 failures');
  // audit
  const au = await admin('/admin/api/audit?ticket=TK-15345');
  const ev = au.j.events.map((e) => e.event);
  ok(ev.includes('issued') && ev.includes('redeemed') && ev.includes('redeem_failed'), 'audit: issued/redeemed/failed for ticket');
  const red = au.j.events.find((e) => e.event === 'redeemed');
  ok(red.device_label === 'L-5CD2419P4Y' && red.device_id === 'dev-A' && red.ext_version === '1.4.0' && red.at > 0, 'audit: device + redeem time recorded');
  const iss1 = au.j.events.find((e) => e.event === 'issued');
  ok(iss1.actor === 'zack@unite-networks.com' && iss1.origin === 'https://app.thecosechouse.co.uk', 'audit: issuer + origin recorded');
  ok(!JSON.stringify(au.j).includes(iss.j.code), 'audit: plaintext code never stored');
} finally {
  try { process.kill(-dev.pid); } catch {}
  rmSync('.dev.vars', { force: true });
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
