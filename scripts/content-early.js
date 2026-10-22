/**
 * content-early.js — Anti-analysis signal collector
 *
 * Runs at document_start (before any page script) to intercept browser
 * primitives that phishing kits use for anti-analysis evasion:
 *
 *   • Self-fetch / self-XHR polling  — PhaaS kits poll their own URL via
 *     setInterval + fetch to detect DevTools (403 = busted → reload page).
 *   • Rapid setInterval              — Very short intervals indicate polling.
 *
 * Results are stored in window.__checkAntiAnalysis and dispatched as a
 * CustomEvent so the document_idle content script can add them to the
 * phishing score without needing a round-trip.
 *
 * This script only activates when the URL already looks suspicious
 * (quick subset score ≥ 40) to avoid any overhead on legitimate pages.
 * Wrapping fetch / XHR / setInterval on real SSO logins breaks those pages.
 */

(function () {
  'use strict';

  const SSO_QUERY_PARAMS = new Set([
    'code', 'state', 'nonce', 'token', 'id_token', 'access_token', 'refresh_token',
    'session_state', 'sessionid', 'session', 'sid', 'jwt', 'assertion',
    'client_id', 'redirect', 'redirect_uri', 'request', 'request_uri',
    'samlrequest', 'samlresponse', 'relaystate', 'wresult', 'wctx', 'wa',
    'scope', 'response', 'error', 'error_description', 'iss', 'aud', 'sub',
    'challenge', 'verifier', 'code_challenge', 'code_verifier',
    'fromuri', 'returl', 'returnurl', 'return_to', 'continue', 'target', 'next',
    'callback', 'postback', 'ticket', 'payload', 'data', 'hash', 'hmac',
    'signature', 'sig', 'csrf', 'xsrf', 'context', 'authorization', 'auth',
    'access', 'idtoken', 'accesstoken', 'response_type', 'response_mode',
    'prompt', 'login_hint', 'domain_hint', 'resource',
  ]);

  function hostnameHasKeywordToken(hostname, keyword) {
    const labels = hostname.split('.');
    for (const label of labels) {
      if (label === keyword) return true;
      if (label.split('-').includes(keyword)) return true;
    }
    return false;
  }

  function hasSpearPhishingTrackingId(search) {
    if (!search) return false;
    const pattern = /[?&]([a-z_-]{1,8})=([A-Za-z0-9_\-]{40,})/gi;
    let match;
    while ((match = pattern.exec(search)) !== null) {
      if (!SSO_QUERY_PARAMS.has(match[1].toLowerCase())) return true;
    }
    return false;
  }

  // ── Quick URL suspiciousness pre-check ──────────────────────────────────
  // Mirror of the key signals from scoreGenericPhishingUrl — kept minimal
  // so this runs in < 1ms on every page load.
  function quickUrlScore() {
    try {
      const parsed = new URL(window.location.href);
      const hostname = parsed.hostname.toLowerCase();
      let s = 0;
      if (hasSpearPhishingTrackingId(parsed.search)) s += 50;
      if (hostnameHasKeywordToken(hostname, 'mail') ||
          hostnameHasKeywordToken(hostname, 'login') ||
          hostnameHasKeywordToken(hostname, 'auth') ||
          hostnameHasKeywordToken(hostname, 'secure') ||
          hostnameHasKeywordToken(hostname, 'webmail') ||
          hostnameHasKeywordToken(hostname, 'internalserver') ||
          hostnameHasKeywordToken(hostname, 'signin') ||
          hostnameHasKeywordToken(hostname, 'account')) {
        s += 20;
      }
      return s;
    } catch (_) { return 0; }
  }

  // Only activate on URLs that already look suspicious.
  if (quickUrlScore() < 40) return;

  // ── Shared signal store ──────────────────────────────────────────────────
  window.__checkAntiAnalysis = { signals: [], score: 0, _selfFetchCount: 0 };

  function reportSignal(type, points, desc) {
    // Deduplicate — only report each signal type once
    if (window.__checkAntiAnalysis.signals.find(s => s.type === type)) return;
    window.__checkAntiAnalysis.signals.push({ type, desc });
    window.__checkAntiAnalysis.score += points;
    try {
      document.dispatchEvent(new CustomEvent('__check_antianalysis', {
        detail: { type, points, desc },
        bubbles: false,
      }));
    } catch (_) {}
  }

  // ── Intercept fetch — detect self-polling ────────────────────────────────
  const _fetch = window.fetch;
  window.fetch = function (resource, init) {
    try {
      const url = typeof resource === 'string' ? resource
                : (resource && resource.url) ? resource.url : '';
      if (url && new URL(url, location.href).pathname === location.pathname) {
        window.__checkAntiAnalysis._selfFetchCount++;
        if (window.__checkAntiAnalysis._selfFetchCount >= 2) {
          reportSignal(
            'self_fetch_polling', 40,
            'Page polls own URL via fetch (DevTools detection / anti-analysis)'
          );
        }
      }
    } catch (_) {}
    return _fetch.apply(this, arguments);
  };

  // ── Intercept XMLHttpRequest — detect self-XHR polling ──────────────────
  const _xhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    try {
      if (url && new URL(url, location.href).pathname === location.pathname) {
        window.__checkAntiAnalysis._selfFetchCount++;
        if (window.__checkAntiAnalysis._selfFetchCount >= 2) {
          reportSignal(
            'self_xhr_polling', 40,
            'Page polls own URL via XHR (DevTools detection / anti-analysis)'
          );
        }
      }
    } catch (_) {}
    return _xhrOpen.apply(this, arguments);
  };

  // ── Detect debugger-trap setInterval ────────────────────────────────────
  // Some kits run `setInterval(() => { debugger; }, 100)` to freeze DevTools.
  // We can't safely intercept the debugger statement itself, but we CAN flag
  // very-rapid intervals (< 200 ms) which serve no legitimate UI purpose.
  const _setInterval = window.setInterval;
  let _rapidIntervalCount = 0;
  window.setInterval = function (fn, delay) {
    if (typeof delay === 'number' && delay > 0 && delay < 200) {
      if (++_rapidIntervalCount >= 2) {
        reportSignal(
          'rapid_interval', 20,
          'Multiple very-rapid setInterval calls (< 200 ms) — anti-analysis pattern'
        );
      }
    }
    return _setInterval.apply(this, arguments);
  };

})();
