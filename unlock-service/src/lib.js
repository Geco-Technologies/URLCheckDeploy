// Pure helpers (shared by the Worker and unit tests).
export const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function generateCode(len = 10) {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  let s = '';
  for (const b of bytes) s += CROCKFORD[b & 31]; // 256 % 32 == 0 -> unbiased
  return s.slice(0, 5) + '-' + s.slice(5);
}

/** Uppercase, drop separators, Crockford aliases (I/L->1, O->0). */
export function normalizeCode(code) {
  return String(code || '')
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0');
}

export function isWellFormedCode(n) {
  return /^[0-9A-HJKMNP-TV-Z]{10}$/.test(n);
}

/** scheme://host[:non-default-port], lowercase host. Accepts a full URL or bare host. */
export function normalizeOrigin(input) {
  let v = String(input || '').trim();
  if (!v) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) v = 'https://' + v;
  try {
    const u = new URL(v);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    if (u.username || u.password) return null;
    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    if (!host || !/^[a-z0-9.-]+$|^\[[0-9a-f:]+\]$/.test(host)) return null;
    const def = u.protocol === 'https:' ? '443' : '80';
    const port = u.port && u.port !== def ? ':' + u.port : '';
    return `${u.protocol}//${host}${port}`;
  } catch {
    return null;
  }
}

export function normalizeTicket(t) {
  const v = String(t || '').trim().toUpperCase().replace(/\s+/g, '');
  const m = v.match(/^(?:TK-?)?(\d{3,8})$/);
  return m ? `TK-${m[1]}` : null;
}

export async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * Verify a Cloudflare Access JWT (RS256). jwks = {keys:[...]}.
 * Returns the payload or throws.
 */
export async function verifyAccessJwt(token, { jwks, aud, issuer, now = Date.now() }) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('malformed jwt');
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
  const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
  if (header.alg !== 'RS256') throw new Error('bad alg');
  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('unknown kid');
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToBytes(parts[2]),
    new TextEncoder().encode(parts[0] + '.' + parts[1]));
  if (!ok) throw new Error('bad signature');
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud || !auds.includes(aud)) throw new Error('bad aud');
  if (issuer && payload.iss !== issuer) throw new Error('bad iss');
  const t = Math.floor(now / 1000);
  if (typeof payload.exp !== 'number' || payload.exp < t) throw new Error('expired');
  if (typeof payload.nbf === 'number' && payload.nbf > t + 60) throw new Error('not yet valid');
  return payload;
}

export function emailAllowed(email, domainsCsv) {
  const e = String(email || '').toLowerCase();
  const at = e.lastIndexOf('@');
  if (at < 1) return false;
  const dom = e.slice(at + 1);
  return String(domainsCsv || '').split(',').map((d) => d.trim().toLowerCase()).filter(Boolean)
    .some((d) => dom === d);
}
