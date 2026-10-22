/**
 * Device-code heuristics for content scripts (classic IIFE).
 * Mirrors scripts/modules/device-code-detector.js — keep in sync conceptually.
 * Phase 3 ClickFix DOM/clipboard detectors are NOT included.
 */
(function (global) {
  "use strict";

  var MS_PATHS = ["/devicelogin", "/deviceloginus", "/device-login"];
  var AKA_PATHS = ["/devicelogin", "/deviceloginus"];
  var LOOKALIKE_TOKENS = [
    "devicelogin",
    "device-login",
    "device_login",
    "devicecode",
    "device-code",
    "device_code",
    "microsoftonline",
    "microsft",
    "rnicrosoft",
    "xn--",
  ];
  var INSTRUCTIONAL_PHRASES = [
    /enter\s+(this\s+)?code/i,
    /device\s*code/i,
    /user\s*code/i,
    /verification\s*code/i,
    /visit\s+microsoft\.com\/devicelogin/i,
    /go\s+to\s+microsoft\.com\/devicelogin/i,
    /aka\.ms\/devicelogin/i,
    /microsoft\.com\/devicelogin/i,
    /open\s+a\s+browser/i,
    /navigate\s+to/i,
  ];
  var SHORT_CODE_RE = /\b[A-Z0-9]{4,5}(?:-[A-Z0-9]{4,5})?\b/;

  var ENTRA_DEVICEAUTH_HOSTS = {
    "login.microsoftonline.com": true,
    "login.microsoftonline.us": true,
    "login.microsoft.com": true,
    "login.windows.net": true,
    "login.partner.microsoftonline.cn": true,
  };

  function isEntraDeviceAuthPath(pathname) {
    var path = (pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";
    return /(?:^|\/)oauth2\/deviceauth(?:\/|$)/.test(path);
  }

  function isLegitimateDeviceLoginUrl(urlString) {
    try {
      var u = new URL(urlString);
      if (u.protocol !== "https:" && u.protocol !== "http:") return false;
      var host = u.hostname.toLowerCase().replace(/\.$/, "");
      var path = (u.pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";
      if (host === "microsoft.com" || host === "www.microsoft.com") {
        return MS_PATHS.some(function (p) {
          return path === p || path.indexOf(p + "/") === 0;
        });
      }
      if (host === "aka.ms") {
        return AKA_PATHS.some(function (p) {
          return path === p || path.indexOf(p + "/") === 0;
        });
      }
      if (ENTRA_DEVICEAUTH_HOSTS[host]) {
        return isEntraDeviceAuthPath(u.pathname);
      }
      return false;
    } catch (_) {
      return false;
    }
  }

  function isTrustedMicrosoftFamilyHost(hostname) {
    var h = String(hostname || "")
      .toLowerCase()
      .replace(/\.$/, "");
    if (!h) return false;
    var suffixes = [
      "microsoft.com",
      "microsoftonline.com",
      "microsoftonline.us",
      "microsoft.us",
      "live.com",
      "office.com",
      "office365.com",
      "windows.net",
      "azure.com",
      "msftauth.net",
      "msauth.net",
      "msn.com",
      "aka.ms",
      "microsoftonline-p.com",
      "microsoftazuread-sso.com",
      "windowsazure.com",
    ];
    return suffixes.some(function (s) {
      return h === s || h.slice(-(s.length + 1)) === "." + s;
    });
  }

  function detectDeviceCodeLookalike(urlString) {
    var reasons = [];
    var score = 0;
    try {
      var u = new URL(urlString);
      var host = u.hostname.toLowerCase();
      if (isTrustedMicrosoftFamilyHost(host)) {
        return { detected: false, confidence: 0, reasons: [], action: "warn", score: 0 };
      }
      var hostCompact = host.replace(/[^a-z0-9]/g, "");
      var path = (u.pathname || "").toLowerCase();
      LOOKALIKE_TOKENS.forEach(function (tok) {
        var t = tok.replace(/[^a-z0-9]/g, "");
        if (t && hostCompact.indexOf(t) !== -1) {
          score += tok.indexOf("micro") !== -1 || tok.indexOf("xn") === 0 ? 35 : 25;
          reasons.push("host_token:" + tok);
        }
        if (path.indexOf(tok.replace(/_/g, "-")) !== -1 || path.indexOf(tok) !== -1) {
          score += 15;
          reasons.push("path_token:" + tok);
        }
      });
      if (/m[i1l!]cro[s5]oft/i.test(host) || /micro[s5][o0]ft/i.test(host)) {
        score += 40;
        reasons.push("microsoft_homoglyph_host");
      }
    } catch (_) {
      return { detected: false, confidence: 0, reasons: [], action: "warn", score: 0 };
    }
    return {
      detected: score >= 40,
      confidence: Math.min(1, score / 100),
      reasons: reasons,
      action: score >= 70 ? "block" : "warn",
      score: score,
    };
  }

  function collectPageSignals(doc) {
    try {
      doc = doc || document;
      var bodyText = (doc.body && doc.body.innerText) || "";
      var linksHref = Array.prototype.slice
        .call(doc.querySelectorAll("a[href]"), 0, 50)
        .map(function (a) {
          return a.href;
        });
      return { bodyText: bodyText.slice(0, 20000), linksHref: linksHref };
    } catch (_) {
      return { bodyText: "", linksHref: [] };
    }
  }

  function detectDeviceCodeInstructional(urlString, page) {
    page = page || {};
    var reasons = [];
    var score = 0;
    try {
      var u = new URL(urlString);
      if (isTrustedMicrosoftFamilyHost(u.hostname)) {
        return { detected: false, confidence: 0, reasons: [], action: "warn", score: 0 };
      }
    } catch (_) {
      return { detected: false, confidence: 0, reasons: [], action: "warn", score: 0 };
    }
    var bodyText = String(page.bodyText || "");
    var links = Array.isArray(page.linksHref) ? page.linksHref : [];
    var phraseHits = 0;
    INSTRUCTIONAL_PHRASES.forEach(function (re) {
      if (re.test(bodyText)) {
        phraseHits += 1;
        reasons.push("phrase:" + re.source.slice(0, 40));
      }
    });
    if (phraseHits >= 1) score += 20 * Math.min(phraseHits, 3);
    if (SHORT_CODE_RE.test(bodyText)) {
      score += 25;
      reasons.push("short_user_code_pattern");
    }
    var pointsAtReal =
      links.some(function (h) {
        return isLegitimateDeviceLoginUrl(h);
      }) ||
      /https?:\/\/(www\.)?microsoft\.com\/devicelogin/i.test(bodyText) ||
      /https?:\/\/aka\.ms\/devicelogin/i.test(bodyText);
    if (pointsAtReal) {
      score += 40;
      reasons.push("points_to_real_devicelogin");
    }
    if (
      reasons.indexOf("short_user_code_pattern") !== -1 &&
      reasons.indexOf("points_to_real_devicelogin") !== -1
    ) {
      score += 20;
      reasons.push("instructional_combo");
    }
    return {
      detected: score >= 50,
      confidence: Math.min(1, score / 100),
      reasons: reasons,
      action: score >= 80 ? "block" : "warn",
      score: score,
    };
  }

  global.CheckDeviceCodeHeuristics = {
    isLegitimateDeviceLoginUrl: isLegitimateDeviceLoginUrl,
    isTrustedMicrosoftFamilyHost: isTrustedMicrosoftFamilyHost,
    detectDeviceCodeLookalike: detectDeviceCodeLookalike,
    detectDeviceCodeInstructional: detectDeviceCodeInstructional,
    collectPageSignals: collectPageSignals,
  };
})(typeof window !== "undefined" ? window : self);
