/**
 * External Feeds Manager
 * Fetches and caches admin-configured external allowlist and blocklist feeds.
 *
 * Feed format — each feed URL may return either:
 *   • A JSON array of strings:  ["https://example.com/*", "domain.com"]
 *   • A JSON object with an "entries", "urls", or "domains" key
 *   • Plain text, one entry per line (lines starting with # are ignored)
 *
 * Entries are matched against the current page URL using the same
 * wildcard-to-regex conversion as the local urlAllowlist.
 *
 * Results are published to storage.session so content scripts can read
 * them without a message round-trip on every page load.
 */

import { storage } from '../browser-polyfill.js';
import logger from '../utils/logger.js';

const FETCH_TIMEOUT_MS = 10_000;
const SESSION_KEY = 'external_feeds';
const CACHE_KEY = 'external_feeds_cache';
const DEFAULT_UPDATE_INTERVAL_H = 6;

/**
 * Shared-hosting platforms that must never be blocked at the domain level.
 * Threat-intel feeds (e.g. URLhaus) frequently contain malicious paths on these
 * domains, but blocking the whole domain would break legitimate services.
 * The content script still checks the full URL against the blocklist for these
 * domains — only the network-level DNR rule is skipped.
 */
const SHARED_HOSTING_DOMAINS = new Set([
  'github.com',
  'raw.githubusercontent.com',
  'githubusercontent.com',
  'gist.github.com',
  'pastebin.com',
  'paste.ee',
  'hastebin.com',
  'discord.com',
  'discordapp.com',
  'cdn.discordapp.com',
  'media.discordapp.net',
  'dropbox.com',
  'dl.dropboxusercontent.com',
  'onedrive.live.com',
  'sharepoint.com',
  '1drv.ms',
  'drive.google.com',
  'docs.google.com',
  'googleusercontent.com',
  'storage.googleapis.com',
  'amazonaws.com',
  's3.amazonaws.com',
  'cloudfront.net',
  'azurewebsites.net',
  'blob.core.windows.net',
  'web.app',
  'firebaseapp.com',
  'netlify.app',
  'vercel.app',
  'pages.dev',
  'glitch.me',
  'replit.com',
  'repl.co',
  'notion.so',
  'anonfiles.com',
  'file.io',
  'transfer.sh',
  'sendspace.com',
  'mediafire.com',
  'mega.nz',
  'mega.co.nz',
  'zippyshare.com',
  'archive.org',
  'web.archive.org',
  'ia601500.us.archive.org',
]);

export class ExternalFeedsManager {
  constructor() {
    this.allowlistPatterns = [];
    this.blocklistEntries  = [];
    this.feedMeta          = {}; // url → { lastUpdate, count, error, type }
    this.updateIntervalMs  = DEFAULT_UPDATE_INTERVAL_H * 3_600_000;
    this.allowlistFeedUrls = [];
    this.blocklistFeedUrls = [];
    this.initialized       = false;
  }

  // ── Lifecycle ────────────────────────────────────────────────────────────

  async initialize(config = {}) {
    try {
      this.allowlistFeedUrls = Array.isArray(config.externalAllowlistFeeds)
        ? config.externalAllowlistFeeds.filter(Boolean)
        : [];
      this.blocklistFeedUrls = Array.isArray(config.externalBlocklistFeeds)
        ? config.externalBlocklistFeeds.filter(Boolean)
        : [];
      this.updateIntervalMs =
        ((config.feedsUpdateInterval ?? DEFAULT_UPDATE_INTERVAL_H) || DEFAULT_UPDATE_INTERVAL_H)
        * 3_600_000;

      await this._loadFromCache();

      // Always re-publish to session storage after loading from cache so the
      // content script can read the entries immediately — session storage is
      // cleared on every browser/service-worker restart, but local cache is not.
      await this._publishToSession();

      // Sync blocklist to declarativeNetRequest session rules so redirecting URLs
      // are blocked at the network level before any redirect can be followed.
      await this._syncToDeclarativeNetRequest();

      // Refresh in background if any feed is stale
      if (this._anyFeedStale()) {
        this._updateFeeds().catch(err =>
          logger.warn('ExternalFeedsManager: background refresh failed:', err.message)
        );
      }

      this.initialized = true;
      logger.log(
        `ExternalFeedsManager initialised: ` +
        `${this.allowlistFeedUrls.length} allowlist feed(s), ` +
        `${this.blocklistFeedUrls.length} blocklist feed(s), ` +
        `${this.allowlistPatterns.length} cached allow patterns, ` +
        `${this.blocklistEntries.length} cached block entries`
      );
    } catch (err) {
      logger.error('ExternalFeedsManager.initialize failed:', err.message);
    }
  }

  async forceUpdate() {
    logger.log('ExternalFeedsManager: force update requested');
    await this._updateFeeds();
    return this.getStatus();
  }

  // ── Public checks ────────────────────────────────────────────────────────

  /** Returns true if the URL matches any external allowlist pattern. */
  isAllowlisted(url) {
    return this._matchesAny(url, this.allowlistPatterns);
  }

  /** Returns true if the URL matches any external blocklist entry. */
  isBlocked(url) {
    return this._matchesAny(url, this.blocklistEntries);
  }

  getStatus() {
    return {
      initialized:    this.initialized,
      allowlistCount: this.allowlistPatterns.length,
      blocklistCount: this.blocklistEntries.length,
      feedMeta:       { ...this.feedMeta },
      feeds: {
        allowlist: [...this.allowlistFeedUrls],
        blocklist: [...this.blocklistFeedUrls],
      },
    };
  }

  // ── Private helpers ──────────────────────────────────────────────────────

  _anyFeedStale() {
    const allUrls = [...this.allowlistFeedUrls, ...this.blocklistFeedUrls];
    if (allUrls.length === 0) return false;
    const now = Date.now();
    return allUrls.some(url => {
      const meta = this.feedMeta[url];
      return !meta || (now - (meta.lastUpdate || 0)) > this.updateIntervalMs;
    });
  }

  async _loadFromCache() {
    try {
      const result = await storage.local.get([CACHE_KEY]);
      const cached = result?.[CACHE_KEY];
      if (cached) {
        this.allowlistPatterns = cached.allowlistPatterns || [];
        this.blocklistEntries  = cached.blocklistEntries  || [];
        this.feedMeta          = cached.feedMeta          || {};
        logger.log(
          `External feeds loaded from cache: ` +
          `${this.allowlistPatterns.length} allow, ${this.blocklistEntries.length} block`
        );
      }
    } catch (err) {
      logger.warn('ExternalFeedsManager: cache load failed:', err.message);
    }
  }

  async _saveToCache() {
    try {
      await storage.local.set({
        [CACHE_KEY]: {
          allowlistPatterns: this.allowlistPatterns,
          blocklistEntries:  this.blocklistEntries,
          feedMeta:          this.feedMeta,
          savedAt:           Date.now(),
        },
      });
    } catch (err) {
      logger.warn('ExternalFeedsManager: cache save failed:', err.message);
    }
  }

  /** Publish compiled lists to session storage for content-script fast access. */
  async _publishToSession() {
    try {
      await storage.session.set({
        [SESSION_KEY]: {
          allowlistPatterns: this.allowlistPatterns,
          blocklistEntries:  this.blocklistEntries,
          updatedAt:         Date.now(),
        },
      });
    } catch (_) { /* session storage not critical */ }
  }

  /**
   * Sync blocklist entries to declarativeNetRequest session rules.
   * This blocks at the network level — before any server-side redirect can be
   * followed — which the content-script approach cannot achieve.
   */
  async _syncToDeclarativeNetRequest() {
    if (!chrome?.declarativeNetRequest?.updateSessionRules) return;
    try {
      // Remove all existing session rules set by this extension
      const existing = await chrome.declarativeNetRequest.getSessionRules();
      const removeRuleIds = existing.map(r => r.id);

      // Extract unique hostnames and use domain-anchor rules (||hostname).
      // This has two advantages over per-URL rules:
      //   1. Deduplication — many URLhaus entries share a domain, so unique
      //      domain count is far lower than entry count.
      //   2. Coverage — ||hostname blocks every path on that domain, so a
      //      redirect to /newpath on the same server is still caught.
      const allDomains = [...new Set(
        this.blocklistEntries.map(url => {
          try { return new URL(url).hostname; } catch (_) { return null; }
        }).filter(Boolean)
      )];

      // Exclude shared-hosting platforms — blocking the whole domain would
      // break legitimate services (e.g. github.com, dropbox.com).
      // The content script still checks the full URL for these domains.
      const sharedHostingSkipped = allDomains.filter(d => SHARED_HOSTING_DOMAINS.has(d));
      const uniqueDomains = allDomains.filter(d => !SHARED_HOSTING_DOMAINS.has(d));

      if (sharedHostingSkipped.length > 0) {
        logger.log(`ExternalFeedsManager: skipping ${sharedHostingSkipped.length} shared-hosting domain(s) from DNR (content script still checks full URLs): ${sharedHostingSkipped.join(', ')}`);
      }

      const hardLimit =
        chrome.declarativeNetRequest.MAX_NUMBER_OF_DYNAMIC_AND_SESSION_RULES ?? 5000;
      const domains = uniqueDomains.slice(0, hardLimit);
      logger.log(`ExternalFeedsManager: DNR limit=${hardLimit}, unique domains=${uniqueDomains.length} (${allDomains.length} total, ${sharedHostingSkipped.length} shared-hosting excluded), adding=${domains.length}`);

      // Redirect to the extension's blocked.html so users see the URLCheck block
      // page rather than Chrome's generic ERR_BLOCKED_BY_CLIENT error.
      // We use regexFilter + regexSubstitution so the original URL is forwarded
      // as a query parameter — blocked.html can then display it.
      // The extension ID is needed to build the chrome-extension:// redirect URL.
      const extId  = chrome.runtime.id;
      const reason = encodeURIComponent('URL blocked by threat intelligence feed');
      const addRules = domains.map((hostname, i) => ({
        id: i + 1,
        priority: 1,
        action: {
          type: 'redirect',
          redirect: {
            regexSubstitution:
              `chrome-extension://${extId}/blocked.html` +
              `?url=\\0` +
              `&reason=${reason}` +
              `&type=external_blocklist`,
          },
        },
        condition: {
          // regexFilter matches the full URL; \0 in regexSubstitution is the whole match.
          // Escape dots in hostname so they match literally, not as regex wildcards.
          regexFilter: `^https?://${hostname.replace(/\./g, '\\.')}(/.*)?$`,
          resourceTypes: ['main_frame', 'sub_frame'],
        },
      }));

      await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds, addRules });

      // Confirm how many rules are actually active
      const active = await chrome.declarativeNetRequest.getSessionRules();
      logger.log(`ExternalFeedsManager: DNR session rules active after sync: ${active.length}`);

      if (uniqueDomains.length > domains.length) {
        logger.warn(`ExternalFeedsManager: ${uniqueDomains.length - domains.length} domains exceed DNR limit and are only covered by content-script blocking`);
      }
    } catch (err) {
      logger.warn('ExternalFeedsManager: DNR sync failed:', err.message);
    }
  }

  async _updateFeeds() {
    const newAllow = [];
    const newBlock = [];

    for (const url of this.allowlistFeedUrls) {
      try {
        const entries = await this._fetchFeed(url);
        newAllow.push(...entries);
        this.feedMeta[url] = { lastUpdate: Date.now(), count: entries.length, error: null, type: 'allowlist' };
        logger.log(`Allowlist feed OK: ${url} (${entries.length} entries)`);
      } catch (err) {
        logger.warn(`Allowlist feed FAILED: ${url}:`, err.message);
        this.feedMeta[url] = { ...(this.feedMeta[url] || {}), error: err.message, type: 'allowlist' };
      }
    }

    for (const url of this.blocklistFeedUrls) {
      try {
        const entries = await this._fetchFeed(url);
        newBlock.push(...entries);
        this.feedMeta[url] = { lastUpdate: Date.now(), count: entries.length, error: null, type: 'blocklist' };
        logger.log(`Blocklist feed OK: ${url} (${entries.length} entries)`);
      } catch (err) {
        logger.warn(`Blocklist feed FAILED: ${url}:`, err.message);
        this.feedMeta[url] = { ...(this.feedMeta[url] || {}), error: err.message, type: 'blocklist' };
      }
    }

    this.allowlistPatterns = [...new Set(newAllow)];
    this.blocklistEntries  = [...new Set(newBlock)];

    await this._saveToCache();
    await this._publishToSession();
    await this._syncToDeclarativeNetRequest();
  }

  async _fetchFeed(url) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    try {
      const resp = await fetch(url, { signal: ctrl.signal, cache: 'no-cache' });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const text = await resp.text();
      return this._parseFeed(text);
    } finally {
      clearTimeout(timer);
    }
  }

  _parseFeed(text) {
    // Try JSON first
    try {
      const json = JSON.parse(text);
      if (Array.isArray(json))       return json.map(String).filter(Boolean);
      if (Array.isArray(json.entries)) return json.entries.map(String).filter(Boolean);
      if (Array.isArray(json.urls))    return json.urls.map(String).filter(Boolean);
      if (Array.isArray(json.domains)) return json.domains.map(String).filter(Boolean);
    } catch (_) { /* not JSON — fall through to plain text */ }

    // Plain text: one entry per line, # = comment
    return text
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'));
  }

  /**
   * Match url against a list of patterns.
   * Patterns may be:
   *   • Regex strings (tested via new RegExp)
   *   • Wildcard URL strings (e.g. https://example.com/*) — converted to regex
   *   • Plain domain/URL substrings — tested via String.includes
   */
  _matchesAny(url, patterns) {
    for (const raw of patterns) {
      if (!raw) continue;
      try {
        // If it looks like a plain wildcard URL, convert * → .*
        const pattern = raw.includes('*')
          ? raw.replace(/[.+?^${}()|[\]\\]/g, c => c === '*' ? '.*' : '\\' + c)
          : raw;
        if (new RegExp(pattern, 'i').test(url)) return true;
      } catch (_) {
        // Fallback: plain substring match
        if (url.includes(raw)) return true;
      }
    }
    return false;
  }
}

export default ExternalFeedsManager;
