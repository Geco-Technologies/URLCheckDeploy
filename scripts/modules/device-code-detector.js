/**
 * Device-code phishing + legitimate verification URI detector (Phase 1 + 2)
 *
 * Phase 2: hard-block real Microsoft device-login verification URIs
 *          (microsoft.com/devicelogin, aka.ms/devicelogin, Entra /oauth2/deviceauth UX)
 * Phase 1: lookalike hosts + instructional pages that coach users into
 *          entering an attacker device code at the real Microsoft URI.
 *
 * Does NOT match normal interactive OAuth authorize/token paths or the
 * protocol /oauth2/v2.0/devicecode endpoint (CA remains the token control).
 * ClickFix DOM/clipboard detectors are intentionally NOT implemented here.
 */

/** Pathnames on microsoft.com / www.microsoft.com that are device-login UX */
const MS_DEVICELOGIN_PATHS = [
  "/devicelogin",
  "/deviceloginus",
  "/device-login",
];

/** aka.ms shortlinks that resolve to device login */
const AKA_DEVICELOGIN_PATHS = ["/devicelogin", "/deviceloginus"];

/** Login hosts that serve the Entra device-auth browser UX */
const ENTRA_DEVICEAUTH_HOSTS = new Set([
  "login.microsoftonline.com",
  "login.microsoftonline.us",
  "login.microsoft.com",
  "login.windows.net",
  "login.partner.microsoftonline.cn",
]);

/**
 * True if pathname is the Entra device-auth *browser UX* (not authorize/token/devicecode).
 * Matches /{tenant}/oauth2/deviceauth and trailing subpaths; rejects authorize/token/devicecode.
 */
function isEntraDeviceAuthPath(pathname) {
  const path = (pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";
  // Require /oauth2/deviceauth as a path segment (not substring of another token)
  return /(?:^|\/)oauth2\/deviceauth(?:\/|$)/.test(path);
}

/**
 * Returns true if URL is a real Microsoft/Aka/Entra device-login verification page
 * that Unite hard-blocks (browser lure), not a normal authorize/token endpoint.
 */
export function isLegitimateDeviceLoginUrl(urlString) {
  try {
    const u = new URL(urlString);
    if (u.protocol !== "https:" && u.protocol !== "http:") return false;
    const host = u.hostname.toLowerCase().replace(/\.$/, "");
    const path = (u.pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";

    if (host === "microsoft.com" || host === "www.microsoft.com") {
      return MS_DEVICELOGIN_PATHS.some(
        (p) => path === p || path.startsWith(p + "/")
      );
    }
    if (host === "aka.ms") {
      return AKA_DEVICELOGIN_PATHS.some(
        (p) => path === p || path.startsWith(p + "/")
      );
    }
    if (ENTRA_DEVICEAUTH_HOSTS.has(host)) {
      return isEntraDeviceAuthPath(u.pathname);
    }
    return false;
  } catch (_) {
    return false;
  }
}

/** Hosts that must never be treated as lookalike / instructional targets */
export function isTrustedMicrosoftFamilyHost(hostname) {
  const h = String(hostname || "").toLowerCase().replace(/\.$/, "");
  if (!h) return false;
  const suffixes = [
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
  return suffixes.some((s) => h === s || h.endsWith("." + s));
}

const LOOKALIKE_TOKENS = [
  "devicelogin",
  "device-login",
  "device_login",
  "devicecode",
  "device-code",
  "device_code",
  "microsoftonline",
  "microsft",
  "rnicrosoft",
  "mícrosoft",
  "xn--", // punycode hint
];

const INSTRUCTIONAL_PHRASES = [
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

const SHORT_CODE_RE = /\b[A-Z0-9]{4,5}(?:-[A-Z0-9]{4,5})?\b/;

/**
 * Score lookalike device-login host (non-MS).
 * @returns {{detected:boolean, confidence:number, reasons:string[], action:'warn'|'block'}}
 */
export function detectDeviceCodeLookalike(urlString) {
  const reasons = [];
  let score = 0;
  try {
    const u = new URL(urlString);
    const host = u.hostname.toLowerCase();
    if (isTrustedMicrosoftFamilyHost(host)) {
      return { detected: false, confidence: 0, reasons: [], action: "warn" };
    }
    const hostCompact = host.replace(/[^a-z0-9]/g, "");
    const path = (u.pathname || "").toLowerCase();

    for (const tok of LOOKALIKE_TOKENS) {
      const t = tok.replace(/[^a-z0-9]/g, "");
      if (t && hostCompact.includes(t)) {
        score += tok.includes("micro") || tok.startsWith("xn") ? 35 : 25;
        reasons.push(`host_token:${tok}`);
      }
      if (path.includes(tok.replace(/_/g, "-")) || path.includes(tok)) {
        score += 15;
        reasons.push(`path_token:${tok}`);
      }
    }

    // Homoglyph / leet microsoft
    if (/m[i1l!]cro[s5]oft/i.test(host) || /micro[s5][o0]ft/i.test(host)) {
      score += 40;
      reasons.push("microsoft_homoglyph_host");
    }
  } catch (_) {
    return { detected: false, confidence: 0, reasons: [], action: "warn" };
  }

  const confidence = Math.min(1, score / 100);
  const detected = score >= 40;
  const action = score >= 70 ? "block" : "warn";
  return { detected, confidence, reasons, action, score };
}

/**
 * Detect instructional device-code phishing page (DOM + URL).
 * Pass document-like { bodyText, linksHref: string[] }.
 */
export function detectDeviceCodeInstructional(urlString, page = {}) {
  const reasons = [];
  let score = 0;
  try {
    const u = new URL(urlString);
    if (isTrustedMicrosoftFamilyHost(u.hostname)) {
      return { detected: false, confidence: 0, reasons: [], action: "warn" };
    }
  } catch (_) {
    return { detected: false, confidence: 0, reasons: [], action: "warn" };
  }

  const bodyText = String(page.bodyText || "");
  const links = Array.isArray(page.linksHref) ? page.linksHref : [];

  let phraseHits = 0;
  for (const re of INSTRUCTIONAL_PHRASES) {
    if (re.test(bodyText)) {
      phraseHits += 1;
      reasons.push(`phrase:${re.source.slice(0, 40)}`);
    }
  }
  if (phraseHits >= 1) score += 20 * Math.min(phraseHits, 3);

  if (SHORT_CODE_RE.test(bodyText)) {
    score += 25;
    reasons.push("short_user_code_pattern");
  }

  const pointsAtReal =
    links.some((h) => {
      try {
        return isLegitimateDeviceLoginUrl(h);
      } catch (_) {
        return false;
      }
    }) ||
    /https?:\/\/(www\.)?microsoft\.com\/devicelogin/i.test(bodyText) ||
    /https?:\/\/aka\.ms\/devicelogin/i.test(bodyText);

  if (pointsAtReal) {
    score += 40;
    reasons.push("points_to_real_devicelogin");
  }

  // Strong combo: code pattern + points at real MS
  if (
    reasons.includes("short_user_code_pattern") &&
    reasons.includes("points_to_real_devicelogin")
  ) {
    score += 20;
    reasons.push("instructional_combo");
  }

  const confidence = Math.min(1, score / 100);
  const detected = score >= 50;
  const action = score >= 80 ? "block" : "warn";
  return { detected, confidence, reasons, action, score };
}

/**
 * Collect lightweight page signals for instructional detector (call from content script).
 */
export function collectPageSignals(doc = document) {
  try {
    const bodyText = (doc.body && doc.body.innerText) || "";
    const linksHref = Array.from(doc.querySelectorAll("a[href]"))
      .map((a) => a.href)
      .slice(0, 50);
    return { bodyText: bodyText.slice(0, 20000), linksHref };
  } catch (_) {
    return { bodyText: "", linksHref: [] };
  }
}

export default {
  isLegitimateDeviceLoginUrl,
  isTrustedMicrosoftFamilyHost,
  detectDeviceCodeLookalike,
  detectDeviceCodeInstructional,
  collectPageSignals,
};
