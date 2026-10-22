// URLCheck online unlock-code service (Option B) — Cloudflare Worker + D1.
//   POST /v1/unlock/redeem        extension (unauthenticated, rate-limited, fleet-wide single use)
//   GET  /v1/health
//   GET  /admin                   generator page        (Cloudflare Access + JWT verified here)
//   POST /admin/api/codes         issue code (ticket mandatory) -> plaintext shown ONCE
//   GET  /admin/api/codes         recent codes (no plaintext, no hashes)
//   POST /admin/api/codes/:id/revoke
//   GET  /admin/api/audit
import {
  generateCode, normalizeCode, isWellFormedCode, normalizeOrigin, normalizeTicket,
  hmacHex, verifyAccessJwt, emailAllowed,
} from './lib.js';
import { ADMIN_HTML } from './admin-html.js';

const FAIL_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS_PER_DEVICE = 5;
const MAX_FAILS_PER_IP = 20;

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...SEC_HEADERS, ...extra },
  });

const SEC_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
};

function clientIp(req) {
  return req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || 'unknown';
}

function int(v, d) { const n = parseInt(v, 10); return Number.isFinite(n) ? n : d; }

async function audit(env, e) {
  await env.DB.prepare(
    `INSERT INTO audit_log (at,event,code_id,ticket,origin,actor,device_id,device_label,ip,ext_version,detail)
     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)`
  ).bind(Date.now(), e.event, e.codeId ?? null, e.ticket ?? null, e.origin ?? null, e.actor ?? null,
    e.deviceId ?? null, e.deviceLabel ?? null, e.ip ?? null, e.extVersion ?? null, e.detail ?? null).run();
}

function pepper(env) {
  if (!env.UNLOCK_PEPPER || String(env.UNLOCK_PEPPER).length < 32) throw new Error('UNLOCK_PEPPER not configured');
  return env.UNLOCK_PEPPER;
}

// ── Extension: redeem ────────────────────────────────────────────────────────
async function redeem(req, env) {
  const reqOrigin = req.headers.get('origin');
  if (reqOrigin && reqOrigin !== `chrome-extension://${env.EXTENSION_ID}`) {
    return json({ ok: false, result: 'forbidden', message: 'Not allowed.' }, 403);
  }
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, result: 'invalid', message: 'Bad request.' }, 400); }
  const ip = clientIp(req);
  const deviceId = String(body.deviceId || '').slice(0, 64) || null;
  const deviceLabel = String(body.deviceLabel || '').slice(0, 64) || null;
  const extVersion = String(body.extVersion || '').slice(0, 20) || null;
  const origin = normalizeOrigin(body.origin || body.url);
  const now = Date.now();
  const since = now - FAIL_WINDOW_MS;

  // Rate limit (failures only) per device and per IP.
  const fails = await env.DB.prepare(
    `SELECT
       SUM(CASE WHEN bucket = ?1 THEN 1 ELSE 0 END) AS dev,
       SUM(CASE WHEN bucket = ?2 THEN 1 ELSE 0 END) AS ip
     FROM redeem_failures WHERE at > ?3 AND bucket IN (?1, ?2)`
  ).bind(`dev:${deviceId}`, `ip:${ip}`, since).first();
  if ((deviceId && (fails?.dev || 0) >= MAX_FAILS_PER_DEVICE) || (fails?.ip || 0) >= MAX_FAILS_PER_IP) {
    await audit(env, { event: 'rate_limited', origin, actor: deviceId, deviceId, deviceLabel, ip, extVersion });
    return json({ ok: false, result: 'rate_limited', message: 'Too many incorrect attempts. Contact Unite helpdesk and try again later.' }, 429);
  }

  const fail = async (result, message, extra = {}) => {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO redeem_failures (bucket, at) VALUES (?1, ?2)').bind(`ip:${ip}`, now),
      ...(deviceId ? [env.DB.prepare('INSERT INTO redeem_failures (bucket, at) VALUES (?1, ?2)').bind(`dev:${deviceId}`, now)] : []),
    ]);
    await audit(env, { event: 'redeem_failed', origin, actor: deviceId, deviceId, deviceLabel, ip, extVersion, detail: result, ...extra });
    return json({ ok: false, result, message, ...(extra.codeId ? { codeId: extra.codeId } : {}) }, 200);
  };

  if (!origin) return fail('invalid', 'Could not determine site origin.');
  const code = normalizeCode(body.code);
  if (!isWellFormedCode(code)) return fail('invalid', 'Invalid unlock code.');
  const hash = await hmacHex(pepper(env), code);

  // Atomic fleet-wide single use: only one UPDATE can flip redeemed_at from NULL.
  const row = await env.DB.prepare(
    `UPDATE unlock_codes
        SET redeemed_at = ?1, redeemed_device = ?2, redeemed_label = ?3, redeemed_ip = ?4
      WHERE code_hash = ?5 AND origin = ?6 AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > ?1
      RETURNING code_id, ticket, grant_ttl_s, origin`
  ).bind(now, deviceId, deviceLabel, ip, hash, origin).first();

  if (row) {
    await audit(env, { event: 'redeemed', codeId: row.code_id, ticket: row.ticket, origin, actor: deviceId, deviceId, deviceLabel, ip, extVersion });
    return json({
      ok: true, result: 'success', message: 'Site unlocked temporarily.',
      origin: row.origin, codeId: row.code_id, ticket: row.ticket,
      unlockTtlSeconds: row.grant_ttl_s, grantExpiresAt: now + row.grant_ttl_s * 1000,
    });
  }

  // Work out why (for the user message + audit). The caller holds the code, so this leaks nothing new.
  const c = await env.DB.prepare('SELECT code_id, ticket, origin, expires_at, redeemed_at, revoked_at FROM unlock_codes WHERE code_hash = ?1')
    .bind(hash).first();
  if (!c) return fail('invalid', 'Invalid unlock code.');
  const ex = { codeId: c.code_id, ticket: c.ticket };
  if (c.revoked_at) return fail('revoked', 'This unlock code has been revoked. Contact Unite helpdesk.', ex);
  if (c.redeemed_at) return fail('used', 'This unlock code has already been used.', ex);
  if (c.expires_at <= now) return fail('expired', 'This unlock code has expired. Request a new one.', ex);
  if (c.origin !== origin) return fail('wrong_origin', 'This unlock code is not valid for this site.', ex);
  return fail('invalid', 'Invalid unlock code.', ex);
}

// ── Admin auth (Cloudflare Access JWT, verified in the Worker too) ──────────
let jwksCache = { at: 0, jwks: null };
async function getJwks(env) {
  if (env.ENVIRONMENT === 'test' && env.ACCESS_TEST_JWKS) return JSON.parse(env.ACCESS_TEST_JWKS);
  if (jwksCache.jwks && Date.now() - jwksCache.at < 10 * 60 * 1000) return jwksCache.jwks;
  const r = await fetch(`https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`);
  if (!r.ok) throw new Error('certs fetch failed');
  jwksCache = { at: Date.now(), jwks: await r.json() };
  return jwksCache.jwks;
}

async function requireAdmin(req, env) {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) {
    return { error: json({ ok: false, message: 'Admin disabled: Cloudflare Access not configured (ACCESS_TEAM_DOMAIN / ACCESS_AUD).' }, 503) };
  }
  const token = req.headers.get('cf-access-jwt-assertion');
  if (!token) return { error: json({ ok: false, message: 'Unauthenticated.' }, 401) };
  try {
    const p = await verifyAccessJwt(token, { jwks: await getJwks(env), aud: env.ACCESS_AUD, issuer: `https://${env.ACCESS_TEAM_DOMAIN}` });
    const email = String(p.email || '').toLowerCase();
    if (!emailAllowed(email, env.ALLOWED_ISSUER_DOMAINS)) return { error: json({ ok: false, message: 'Forbidden.' }, 403) };
    return { email };
  } catch (e) {
    return { error: json({ ok: false, message: 'Unauthenticated.' }, 401) };
  }
}

function sameOriginWrite(req) {
  const o = req.headers.get('origin');
  const host = new URL(req.url).origin;
  return req.headers.get('x-urlcheck-admin') === '1' && (!o || o === host);
}

async function issue(req, env, email) {
  if (!sameOriginWrite(req)) return json({ ok: false, message: 'Bad request.' }, 400);
  let b; try { b = await req.json(); } catch { return json({ ok: false, message: 'Bad request.' }, 400); }
  const ticket = normalizeTicket(b.ticket);
  if (!ticket) return json({ ok: false, message: 'Ticket number is required (e.g. TK-15345).' }, 400);
  const origin = normalizeOrigin(b.origin || b.url);
  if (!origin) return json({ ok: false, message: 'A valid site URL or origin is required.' }, 400);
  const reason = String(b.reason || '').trim().slice(0, 500) || null;
  const maxTtl = int(env.MAX_GRANT_TTL_SECONDS, 28800);
  const grantTtl = Math.min(Math.max(int(b.grantTtlSeconds, int(env.DEFAULT_GRANT_TTL_SECONDS, 14400)), 300), maxTtl);
  const now = Date.now();
  const expiresAt = now + int(env.CODE_TTL_MINUTES, 15) * 60 * 1000;
  const codeId = crypto.randomUUID();
  let code, hash;
  for (let i = 0; i < 5; i++) {
    code = generateCode(10);
    hash = await hmacHex(pepper(env), normalizeCode(code));
    try {
      await env.DB.prepare(
        `INSERT INTO unlock_codes (code_id, code_hash, origin, ticket, reason, issuer_email, created_at, expires_at, grant_ttl_s)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)`
      ).bind(codeId, hash, origin, ticket, reason, email, now, expiresAt, grantTtl).run();
      break;
    } catch (e) { if (i === 4) throw e; }
  }
  await audit(env, { event: 'issued', codeId, ticket, origin, actor: email, ip: clientIp(req), detail: reason });
  return json({ ok: true, code, codeId, origin, ticket, expiresAt, grantTtlSeconds: grantTtl });
}

async function listCodes(env) {
  const { results } = await env.DB.prepare(
    `SELECT code_id, origin, ticket, reason, issuer_email, created_at, expires_at, grant_ttl_s,
            redeemed_at, redeemed_device, redeemed_label, revoked_at, revoked_by
       FROM unlock_codes ORDER BY created_at DESC LIMIT 100`
  ).all();
  const now = Date.now();
  return json({ ok: true, now, codes: results.map((r) => ({
    ...r, status: r.revoked_at ? 'revoked' : r.redeemed_at ? 'redeemed' : r.expires_at <= now ? 'expired' : 'active',
  })) });
}

async function revoke(req, env, email, codeId) {
  if (!sameOriginWrite(req)) return json({ ok: false, message: 'Bad request.' }, 400);
  const r = await env.DB.prepare(
    'UPDATE unlock_codes SET revoked_at = ?1, revoked_by = ?2 WHERE code_id = ?3 AND revoked_at IS NULL RETURNING code_id, ticket, origin, redeemed_at'
  ).bind(Date.now(), email, codeId).first();
  if (!r) return json({ ok: false, message: 'Not found or already revoked.' }, 404);
  await audit(env, { event: 'revoked', codeId, ticket: r.ticket, origin: r.origin, actor: email, ip: clientIp(req),
    detail: r.redeemed_at ? 'already redeemed: existing device grant runs to its TTL' : null });
  return json({ ok: true, codeId, alreadyRedeemed: !!r.redeemed_at });
}

async function listAudit(env, url) {
  const ticket = normalizeTicket(url.searchParams.get('ticket'));
  const stmt = ticket
    ? env.DB.prepare('SELECT * FROM audit_log WHERE ticket = ?1 ORDER BY at DESC LIMIT 200').bind(ticket)
    : env.DB.prepare('SELECT * FROM audit_log ORDER BY at DESC LIMIT 200');
  const { results } = await stmt.all();
  return json({ ok: true, events: results });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;
    try {
      if (p === '/v1/health') return json({ ok: true, env: env.ENVIRONMENT || 'unknown' });
      if (p === '/v1/unlock/redeem') {
        if (req.method !== 'POST') return json({ ok: false }, 405);
        return await redeem(req, env);
      }
      if (p === '/admin' || p.startsWith('/admin/')) {
        const a = await requireAdmin(req, env);
        if (a.error) return a.error;
        if (p === '/admin' || p === '/admin/') {
          return new Response(ADMIN_HTML, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
            'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'", ...SEC_HEADERS } });
        }
        if (p === '/admin/api/me') return json({ ok: true, email: a.email });
        if (p === '/admin/api/codes' && req.method === 'POST') return await issue(req, env, a.email);
        if (p === '/admin/api/codes' && req.method === 'GET') return await listCodes(env);
        const m = p.match(/^\/admin\/api\/codes\/([0-9a-f-]{36})\/revoke$/);
        if (m && req.method === 'POST') return await revoke(req, env, a.email, m[1]);
        if (p === '/admin/api/audit') return await listAudit(env, url);
        return json({ ok: false, message: 'Not found.' }, 404);
      }
      return json({ ok: false, message: 'Not found.' }, 404);
    } catch (e) {
      return json({ ok: false, result: 'error', message: 'Service error.' }, 500);
    }
  },
  async scheduled(_ev, env) {
    await env.DB.prepare('DELETE FROM redeem_failures WHERE at < ?1').bind(Date.now() - 24 * 3600 * 1000).run();
  },
};
