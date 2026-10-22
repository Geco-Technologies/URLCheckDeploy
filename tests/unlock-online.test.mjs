// node tests/unlock-online.test.mjs — Option B online unlock (mocked chrome + fetch).
const store = {};
globalThis.chrome = {
  storage: { local: {
    get: async (keys) => Object.fromEntries((Array.isArray(keys) ? keys : [keys]).filter((k) => k in store).map((k) => [k, structuredClone(store[k])])),
    set: async (o) => { Object.assign(store, structuredClone(o)); },
  } },
  runtime: { getManifest: () => ({ version: '1.4.0' }) },
};
const { UnlockCodeManager } = await import('../scripts/modules/unlock-code-manager.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('PASS', m); } else { fail++; console.log('FAIL', m); } };
const ORIGIN = 'https://app.thecosechouse.co.uk';
const URLX = ORIGIN + '/firstorder.php?utm_medium=email';
const EP = 'https://urlcheck-unlock-staging.example.workers.dev/v1/unlock/redeem';

function mgr({ enterprise = {}, local = {} } = {}) {
  const cfg = { enableUnlockCodes: true, unlockValidationMode: 'policy_list', unlockCodeEntries: [], ...local, ...enterprise };
  return new UnlockCodeManager({ getConfig: async () => cfg, enterpriseConfig: enterprise });
}
const online = (extra = {}) => ({ enterprise: { unlockValidationMode: 'geco_endpoint', unlockEndpointUrl: EP, unlockDeviceLabel: 'L-5CD2419P4Y', ...extra } });
let calls = [];
function mockFetch(fn) { calls = []; globalThis.fetch = async (u, init) => { calls.push({ u, init, body: JSON.parse(init.body) }); return fn(u, init); }; }
const resp = (status, body) => ({ status, json: async () => body });
const reset = () => { for (const k of Object.keys(store)) delete store[k]; };
async function policyEntry(code, origin = ORIGIN) {
  const salt = 'abcd1234';
  const m = new UnlockCodeManager({ getConfig: async () => ({}) });
  return { codeId: 'pol-1', salt, codeHash: await m.sha256Hex(`${salt}:${UnlockCodeManager.normalizeCode(code)}`), origin, singleUse: true };
}
const CODE = 'wsvg2-vdnfq';

// 1 success
reset(); mockFetch(() => resp(200, { ok: true, result: 'success', origin: ORIGIN, codeId: 'c1', ticket: 'TK-15345', unlockTtlSeconds: 14400 }));
let m = mgr(online()); let r = await m.redeem({ code: CODE, url: URLX });
ok(r.ok && r.result === 'success' && r.ticket === 'TK-15345', 'online success');
ok(await m.isOriginUnlocked(URLX) && store.unlockGrants[ORIGIN].source === 'online', 'grant written (source=online)');
const b = calls[0].body;
ok(calls[0].u === EP && b.code === 'WSVG2VDNFQ' && b.origin === ORIGIN && b.deviceLabel === 'L-5CD2419P4Y' && /^[0-9a-f-]{36}$/.test(b.deviceId) && b.extVersion === '1.4.0', 'request body: normalised code, origin, device id/label, version');
ok(calls[0].init.credentials === 'omit' && calls[0].init.redirect === 'error', 'request: no credentials, no redirects');
const dev1 = b.deviceId; await m.redeem({ code: CODE, url: URLX }); ok(calls[0].body.deviceId === dev1, 'device id stable');

// 2 server says different origin
reset(); mockFetch(() => resp(200, { ok: true, origin: 'https://evil.example', codeId: 'c1', unlockTtlSeconds: 14400 }));
r = await mgr(online()).redeem({ code: CODE, url: URLX });
ok(!r.ok && r.result === 'wrong_origin' && !store.unlockGrants?.[ORIGIN], 'server success for other origin -> refused, no grant');

// 3 used / revoked / expired
for (const res of ['used', 'revoked', 'expired', 'wrong_origin', 'invalid']) {
  reset(); mockFetch(() => resp(200, { ok: false, result: res, message: 'msg-' + res }));
  r = await mgr(online()).redeem({ code: CODE, url: URLX });
  ok(!r.ok && r.result === res && r.message === 'msg-' + res && (store.unlockAttemptState?.[ORIGIN]?.failures?.length === 1), `server ${res} -> refused, local failure counted`);
}
// 4 unreachable, no entries
reset(); mockFetch(() => { throw new TypeError('Failed to fetch'); });
r = await mgr(online()).redeem({ code: CODE, url: URLX });
ok(!r.ok && r.result === 'unavailable' && !store.unlockAttemptState?.[ORIGIN], 'unreachable -> unavailable, not counted as failure');
// 5 unreachable -> Option A fallback
reset(); mockFetch(() => { throw new TypeError('Failed to fetch'); });
r = await mgr(online({ unlockCodeEntries: [await policyEntry(CODE)] })).redeem({ code: CODE, url: URLX });
ok(r.ok && store.unlockGrants[ORIGIN].source === 'policy_list', 'unreachable -> policy_list fallback grants');
// 6 5xx -> fallback; server invalid + valid policy entry -> grants
reset(); mockFetch(() => resp(503, { ok: false }));
r = await mgr(online({ unlockCodeEntries: [await policyEntry(CODE)] })).redeem({ code: CODE, url: URLX });
ok(r.ok, '5xx -> policy_list fallback grants');
reset(); mockFetch(() => resp(200, { ok: false, result: 'invalid', message: 'Invalid unlock code.' }));
r = await mgr(online({ unlockCodeEntries: [await policyEntry(CODE)] })).redeem({ code: CODE, url: URLX });
ok(r.ok, 'server invalid but policy entry matches -> grants');
reset(); mockFetch(() => resp(200, { ok: false, result: 'used', message: 'already used' }));
r = await mgr(online({ unlockCodeEntries: [await policyEntry('ZZZZZ-ZZZZZ')] })).redeem({ code: CODE, url: URLX });
ok(!r.ok && r.result === 'used' && r.message === 'already used', 'server used + no policy match -> server message kept');
// 7 rate limited
reset(); mockFetch(() => resp(429, { ok: false, result: 'rate_limited', message: 'Too many' }));
r = await mgr(online()).redeem({ code: CODE, url: URLX });
ok(!r.ok && r.result === 'rate_limited', '429 -> rate_limited');
// 8 endpoint only in LOCAL config -> ignored
reset(); mockFetch(() => resp(200, { ok: true, origin: ORIGIN, unlockTtlSeconds: 14400 }));
r = await mgr({ local: { unlockValidationMode: 'geco_endpoint', unlockEndpointUrl: 'https://attacker.example/redeem' } }).redeem({ code: CODE, url: URLX });
ok(!r.ok && calls.length === 0, 'endpoint from local (non-policy) config is ignored');
// 9 http endpoint refused
reset(); mockFetch(() => resp(200, { ok: true, origin: ORIGIN, unlockTtlSeconds: 14400 }));
r = await mgr(online({ unlockEndpointUrl: 'http://plain.example/redeem' })).redeem({ code: CODE, url: URLX });
ok(!r.ok && calls.length === 0 && r.result === 'unavailable', 'non-https endpoint not called');
// 10 TTL cap
reset(); mockFetch(() => resp(200, { ok: true, origin: ORIGIN, codeId: 'c9', unlockTtlSeconds: 999999 }));
r = await mgr(online()).redeem({ code: CODE, url: URLX });
ok(r.ok && r.unlockTtlSeconds === 28800, 'grant TTL capped at 8h');
// 11 policy_list mode does not call network
reset(); mockFetch(() => resp(200, { ok: true, origin: ORIGIN }));
r = await mgr({ enterprise: { unlockCodeEntries: [await policyEntry(CODE)] } }).redeem({ code: CODE, url: URLX });
ok(r.ok && calls.length === 0, 'policy_list mode unchanged (no network)');
// 12 timeout
reset(); globalThis.fetch = (u, init) => new Promise((_, rej) => init.signal.addEventListener('abort', () => rej(Object.assign(new Error('aborted'), { name: 'AbortError' }))));
const t0 = Date.now(); r = await mgr(online()).redeem({ code: CODE, url: URLX });
ok(!r.ok && r.result === 'unavailable' && Date.now() - t0 < 9500, 'timeout after ~8s -> unavailable');
// 13 feature disabled
reset(); mockFetch(() => resp(200, { ok: true, origin: ORIGIN }));
r = await new UnlockCodeManager({ getConfig: async () => ({ enableUnlockCodes: false }), enterpriseConfig: {} }).redeem({ code: CODE, url: URLX });
ok(!r.ok && r.result === 'feature_disabled' && calls.length === 0, 'enableUnlockCodes=false -> no network');

console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0);
