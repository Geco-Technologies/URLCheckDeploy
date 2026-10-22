/**
 * Unlock Code Manager — Phase 1b Option A (+ Option B online validation)
 *
 * unlockValidationMode = "geco_endpoint" + unlockEndpointUrl (https): codes are
 * validated online by the Unite unlock service (fleet-wide single use, revocable,
 * audited). If the service is unreachable or rejects the code, the offline
 * policy_list entries (Option A) are still tried.
 *
 * Helpdesk-issued unlock codes stored as salted SHA-256 hashes in managed
 * policy (unlockCodeEntries). Origin-bound, single-use on redeem, temporary
 * grant TTL (default 4h). Offline validation. No master PIN / permanent continue.
 */

import logger from "../utils/logger.js";

const STORAGE_GRANTS = "unlockGrants";
const STORAGE_CONSUMED = "unlockConsumedCodeIds";
const STORAGE_ATTEMPTS = "unlockAttemptState";
const STORAGE_DEVICE_ID = "unlockDeviceId";
const ONLINE_TIMEOUT_MS = 8000;
const MAX_ONLINE_GRANT_SECONDS = 28800; // 8h hard cap regardless of server reply

const DEFAULT_TTL_SECONDS = 14400; // 4 hours
const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_ATTEMPT_WINDOW_SECONDS = 900; // 15 minutes

function secureEqual(a, b) {
  const aa = String(a || "");
  const bb = String(b || "").toLowerCase();
  if (aa.length !== bb.length) return false;
  let out = 0;
  for (let i = 0; i < aa.length; i++) {
    out |= aa.charCodeAt(i) ^ bb.charCodeAt(i);
  }
  return out === 0;
}

export class UnlockCodeManager {
  constructor(configManager) {
    this.configManager = configManager;
  }

  /** scheme + host + non-default port; host lowercased */
  static normalizeOrigin(urlOrOrigin) {
    try {
      const u = new URL(urlOrOrigin);
      const host = u.hostname.toLowerCase();
      const defaultPort =
        u.protocol === "https:" ? "443" : u.protocol === "http:" ? "80" : "";
      const port = u.port || defaultPort;
      const portPart = port && port !== defaultPort ? `:${port}` : "";
      return `${u.protocol}//${host}${portPart}`;
    } catch (_) {
      return null;
    }
  }

  static normalizeCode(code) {
    return String(code || "")
      .trim()
      .toUpperCase()
      .replace(/[-\s]/g, "");
  }

  async sha256Hex(message) {
    const data = new TextEncoder().encode(message);
    const digest = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  async getFlags() {
    const config = (await this.configManager.getConfig()) || {};
    return {
      enableUnlockCodes: config.enableUnlockCodes === true,
      unlockValidationMode: config.unlockValidationMode || "policy_list",
      unlockCodeEntries: Array.isArray(config.unlockCodeEntries)
        ? config.unlockCodeEntries
        : [],
      unlockDefaultTtlSeconds:
        Number(config.unlockDefaultTtlSeconds) > 0
          ? Number(config.unlockDefaultTtlSeconds)
          : DEFAULT_TTL_SECONDS,
      unlockMaxAttempts:
        Number(config.unlockMaxAttempts) > 0
          ? Number(config.unlockMaxAttempts)
          : DEFAULT_MAX_ATTEMPTS,
      unlockAttemptWindowSeconds:
        Number(config.unlockAttemptWindowSeconds) > 0
          ? Number(config.unlockAttemptWindowSeconds)
          : DEFAULT_ATTEMPT_WINDOW_SECONDS,
      // Online endpoint is honoured ONLY from enterprise (managed) policy, never from
      // local/options storage, so a user cannot point it at a self-minting server.
      unlockEndpointUrl:
        typeof this.configManager?.enterpriseConfig?.unlockEndpointUrl === "string"
          ? this.configManager.enterpriseConfig.unlockEndpointUrl.trim()
          : "",
      unlockDeviceLabel:
        typeof config.unlockDeviceLabel === "string" ? config.unlockDeviceLabel.trim().slice(0, 64) : "",
      unlockHelpdeskMessage:
        typeof config.unlockHelpdeskMessage === "string" &&
        config.unlockHelpdeskMessage.trim()
          ? config.unlockHelpdeskMessage.trim()
          : "Contact Unite helpdesk (phone/Teams) and ask for an unlock code. Do not enter codes from unsolicited email or chat.",
    };
  }

  async pruneExpiredGrants() {
    const data = await chrome.storage.local.get([STORAGE_GRANTS]);
    const grants = data[STORAGE_GRANTS] || {};
    const now = Date.now();
    let changed = false;
    for (const origin of Object.keys(grants)) {
      if (!grants[origin]?.expiresAt || grants[origin].expiresAt <= now) {
        delete grants[origin];
        changed = true;
      }
    }
    if (changed) {
      await chrome.storage.local.set({ [STORAGE_GRANTS]: grants });
    }
    return grants;
  }

  async getActiveGrant(urlOrOrigin) {
    const origin = UnlockCodeManager.normalizeOrigin(urlOrOrigin);
    if (!origin) return null;
    const grants = await this.pruneExpiredGrants();
    const grant = grants[origin];
    if (!grant || grant.expiresAt <= Date.now()) return null;
    return { origin, ...grant };
  }

  async isOriginUnlocked(urlOrOrigin) {
    return (await this.getActiveGrant(urlOrOrigin)) != null;
  }

  async writeGrant(origin, { ttlSeconds, codeId, source }) {
    const grants = await this.pruneExpiredGrants();
    const now = Date.now();
    grants[origin] = {
      expiresAt: now + ttlSeconds * 1000,
      issuedAt: now,
      codeId: codeId || null,
      source: source || "policy_list",
    };
    await chrome.storage.local.set({ [STORAGE_GRANTS]: grants });
    return grants[origin];
  }

  async markCodeConsumed(codeId) {
    if (!codeId) return;
    const data = await chrome.storage.local.get([STORAGE_CONSUMED]);
    const list = Array.isArray(data[STORAGE_CONSUMED])
      ? data[STORAGE_CONSUMED]
      : [];
    if (!list.includes(codeId)) {
      list.push(codeId);
      while (list.length > 500) list.shift();
      await chrome.storage.local.set({ [STORAGE_CONSUMED]: list });
    }
  }

  async isCodeConsumed(codeId) {
    if (!codeId) return false;
    const data = await chrome.storage.local.get([STORAGE_CONSUMED]);
    const list = Array.isArray(data[STORAGE_CONSUMED])
      ? data[STORAGE_CONSUMED]
      : [];
    return list.includes(codeId);
  }

  async getAttemptState(origin) {
    const data = await chrome.storage.local.get([STORAGE_ATTEMPTS]);
    const all = data[STORAGE_ATTEMPTS] || {};
    return all[origin] || { failures: [] };
  }

  async recordFailure(origin) {
    const data = await chrome.storage.local.get([STORAGE_ATTEMPTS]);
    const all = data[STORAGE_ATTEMPTS] || {};
    const state = all[origin] || { failures: [] };
    const now = Date.now();
    state.failures = (state.failures || []).filter(
      (t) => now - t < 24 * 60 * 60 * 1000
    );
    state.failures.push(now);
    all[origin] = state;
    await chrome.storage.local.set({ [STORAGE_ATTEMPTS]: all });
    return state;
  }

  async clearFailures(origin) {
    const data = await chrome.storage.local.get([STORAGE_ATTEMPTS]);
    const all = data[STORAGE_ATTEMPTS] || {};
    delete all[origin];
    await chrome.storage.local.set({ [STORAGE_ATTEMPTS]: all });
  }

  async isRateLimited(origin, flags) {
    const state = await this.getAttemptState(origin);
    const windowMs = flags.unlockAttemptWindowSeconds * 1000;
    const now = Date.now();
    const recent = (state.failures || []).filter((t) => now - t < windowMs);
    return recent.length >= flags.unlockMaxAttempts;
  }

  /**
   * Redeem plaintext code for blocked URL. Never logs raw code.
   */
  async redeem({ code, url }) {
    const flags = await this.getFlags();
    const origin = UnlockCodeManager.normalizeOrigin(url);
    const base = { origin, url: url || null, codeId: null };

    if (!flags.enableUnlockCodes) {
      return {
        ok: false,
        result: "feature_disabled",
        message: "Unlock codes are disabled by policy.",
        ...base,
      };
    }
    if (!origin) {
      return {
        ok: false,
        result: "invalid",
        message: "Could not determine site origin.",
        ...base,
      };
    }
    if (flags.unlockValidationMode === "off") {
      return {
        ok: false,
        result: "feature_disabled",
        message: "Unlock validation is turned off.",
        ...base,
      };
    }
    if (await this.isRateLimited(origin, flags)) {
      return {
        ok: false,
        result: "rate_limited",
        message:
          "Too many incorrect attempts. Contact Unite helpdesk and try again later.",
        ...base,
      };
    }

    const normalized = UnlockCodeManager.normalizeCode(code);
    if (!normalized || normalized.length < 8) {
      await this.recordFailure(origin);
      return {
        ok: false,
        result: "invalid",
        message: "Invalid unlock code.",
        ...base,
      };
    }

    let online = null;
    if (flags.unlockValidationMode === "geco_endpoint") {
      online = await this.redeemOnline({ flags, origin, url, normalized });
      if (online.ok) {
        await this.clearFailures(origin);
        return online;
      }
      if (online.result === "rate_limited") {
        return { ...base, ...online };
      }
      // Rejected or unreachable: fall through to offline Option A entries.
      if (!flags.unlockCodeEntries.length) {
        if (online.result !== "unavailable") await this.recordFailure(origin);
        return { ...base, ...online, ok: false };
      }
    }

    let matched = null;
    for (const entry of flags.unlockCodeEntries) {
      if (!entry || !entry.salt || !entry.codeHash) continue;
      const entryOrigin = UnlockCodeManager.normalizeOrigin(entry.origin);
      if (!entryOrigin) continue;

      const candidateHash = await this.sha256Hex(`${entry.salt}:${normalized}`);
      if (!secureEqual(candidateHash, String(entry.codeHash).toLowerCase())) {
        continue;
      }

      if (entryOrigin !== origin) {
        await this.recordFailure(origin);
        return {
          ok: false,
          result: "wrong_origin",
          message: "This unlock code is not valid for this site.",
          ...base,
          codeId: entry.codeId || null,
        };
      }

      if (entry.codeExpiresAt) {
        const exp = Date.parse(entry.codeExpiresAt);
        if (!Number.isNaN(exp) && Date.now() > exp) {
          await this.recordFailure(origin);
          return {
            ok: false,
            result: "expired",
            message: "This unlock code has expired. Request a new one.",
            ...base,
            codeId: entry.codeId || null,
          };
        }
      }

      if (entry.singleUse !== false && entry.codeId) {
        if (await this.isCodeConsumed(entry.codeId)) {
          await this.recordFailure(origin);
          return {
            ok: false,
            result: "invalid",
            message: "This unlock code has already been used.",
            ...base,
            codeId: entry.codeId,
          };
        }
      }

      matched = entry;
      break;
    }

    if (!matched) {
      await this.recordFailure(origin);
      if (online && online.result && online.result !== "unavailable") {
        return { ...base, ...online, ok: false };
      }
      return {
        ok: false,
        result: "invalid",
        message: "Invalid unlock code.",
        ...base,
      };
    }

    const ttl =
      Number(matched.unlockTtlSeconds) > 0
        ? Number(matched.unlockTtlSeconds)
        : flags.unlockDefaultTtlSeconds;

    const grant = await this.writeGrant(origin, {
      ttlSeconds: ttl,
      codeId: matched.codeId || null,
      source: "policy_list",
    });

    if (matched.singleUse !== false && matched.codeId) {
      await this.markCodeConsumed(matched.codeId);
    }
    await this.clearFailures(origin);

    logger.log(
      `Unlock granted for ${origin} until ${new Date(grant.expiresAt).toISOString()} (codeId=${matched.codeId || "n/a"})`
    );

    return {
      ok: true,
      result: "success",
      message: "Site unlocked temporarily.",
      origin,
      url,
      codeId: matched.codeId || null,
      expiresAt: grant.expiresAt,
      unlockTtlSeconds: ttl,
      navigateTo: url,
    };
  }
  async getDeviceId() {
    const data = await chrome.storage.local.get([STORAGE_DEVICE_ID]);
    let id = data[STORAGE_DEVICE_ID];
    if (!id || typeof id !== "string") {
      id = crypto.randomUUID();
      await chrome.storage.local.set({ [STORAGE_DEVICE_ID]: id });
    }
    return id;
  }

  static isAllowedEndpoint(u) {
    try {
      const p = new URL(u);
      return p.protocol === "https:" && !p.username && !p.password;
    } catch (_) {
      return false;
    }
  }

  /**
   * Option B: validate + consume the code on the Unite unlock service.
   * Returns { ok, result, message, ... }; result "unavailable" = could not reach / use the service.
   */
  async redeemOnline({ flags, origin, url, normalized }) {
    const unavailable = {
      ok: false,
      result: "unavailable",
      message: "Online unlock validation is unavailable right now. Contact Unite helpdesk.",
    };
    if (!UnlockCodeManager.isAllowedEndpoint(flags.unlockEndpointUrl)) return unavailable;
    let resp;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), ONLINE_TIMEOUT_MS);
    try {
      resp = await fetch(flags.unlockEndpointUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          code: normalized,
          origin,
          url: url || null,
          deviceId: await this.getDeviceId(),
          deviceLabel: flags.unlockDeviceLabel || null,
          extVersion: chrome.runtime?.getManifest?.().version || null,
        }),
        signal: ctl.signal,
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
      });
    } catch (e) {
      logger.warn("Online unlock validation unreachable:", e?.name || e);
      return unavailable;
    } finally {
      clearTimeout(timer);
    }
    let body = null;
    try {
      body = await resp.json();
    } catch (_) {
      return unavailable;
    }
    if (resp.status === 429 || body?.result === "rate_limited") {
      return {
        ok: false,
        result: "rate_limited",
        message: body?.message || "Too many incorrect attempts. Contact Unite helpdesk and try again later.",
      };
    }
    if (resp.status >= 500 || !body || typeof body.ok !== "boolean") return unavailable;
    if (!body.ok) {
      const known = ["invalid", "used", "expired", "revoked", "wrong_origin"];
      const result = known.includes(body.result) ? body.result : "invalid";
      return {
        ok: false,
        result,
        message: typeof body.message === "string" ? body.message.slice(0, 200) : "Invalid unlock code.",
        codeId: body.codeId || null,
      };
    }
    // Success must be for exactly this origin.
    if (UnlockCodeManager.normalizeOrigin(body.origin) !== origin) {
      return { ok: false, result: "wrong_origin", message: "This unlock code is not valid for this site." };
    }
    const ttl = Math.min(
      Number(body.unlockTtlSeconds) > 0 ? Number(body.unlockTtlSeconds) : flags.unlockDefaultTtlSeconds,
      MAX_ONLINE_GRANT_SECONDS
    );
    const grant = await this.writeGrant(origin, { ttlSeconds: ttl, codeId: body.codeId || null, source: "online" });
    logger.log(`Unlock granted (online) for ${origin} until ${new Date(grant.expiresAt).toISOString()} (codeId=${body.codeId || "n/a"}, ticket=${body.ticket || "n/a"})`);
    return {
      ok: true,
      result: "success",
      message: "Site unlocked temporarily.",
      origin,
      url,
      codeId: body.codeId || null,
      ticket: body.ticket || null,
      expiresAt: grant.expiresAt,
      unlockTtlSeconds: ttl,
      navigateTo: url,
    };
  }
}

export default UnlockCodeManager;
