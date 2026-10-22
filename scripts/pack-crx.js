#!/usr/bin/env node
/**
 * Pack the extension as a signed CRX3 file using the crx3 CLI.
 * Reads from the already-clean dist/check-chrome-<version>.zip so only
 * extension files are included (no node_modules, tests, build scripts, etc.).
 *
 * Uses a FIXED CRX filename (check-chrome.crx) so the update_manifest.xml
 * URL never changes between releases. To release a new version:
 *   1. Bump the version in manifest.json
 *   2. Run: npm run pack:crx
 *   3. Upload dist/check-chrome.crx and dist/update_manifest.xml to GitHub
 *      (overwrite the existing files — same URLs, new content)
 *   Chrome/Edge on managed machines will auto-update silently.
 *
 * Outputs (all in dist/):
 *   check.pem          Private key — KEEP SAFE, never commit to git.
 *   check-chrome.crx   Signed CRX3 — upload to GitHub (overwrite each release).
 *   update_manifest.xml  Chrome/Edge update manifest — upload to GitHub (overwrite).
 */

import fs   from 'fs';
import path from 'path';
import { spawnSync }     from 'child_process';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir   = path.join(__dirname, '..');
const distDir   = path.join(rootDir, 'dist');

// GitHub Pages URLs — proper MIME types, never change between releases.
// raw.githubusercontent.com serves everything as text/plain with nosniff,
// which prevents Chrome's updater from parsing the manifest.
// GitHub Pages serves .xml as application/xml which Chrome requires.
const PAGES_BASE   = 'https://geco-technologies.github.io/URLCheckDeploy';
const CRX_URL      = `${PAGES_BASE}/check-chrome.crx`;
const MANIFEST_URL = `${PAGES_BASE}/update_manifest.xml`;

// ── Paths ────────────────────────────────────────────────────────────────────
const manifest = JSON.parse(fs.readFileSync(path.join(rootDir, 'manifest.json'), 'utf8'));
const version  = manifest.version;
const zipPath  = path.join(distDir, `check-chrome-${version}.zip`);
const crxPath  = path.join(distDir, 'check-chrome.crx');       // fixed filename
const pemPath  = path.join(distDir, 'check.pem');
const xmlPath  = path.join(distDir, 'update_manifest.xml');

if (!fs.existsSync(zipPath)) {
  console.error(`\nError: ${zipPath} not found — run "npm run package:chrome" first`);
  process.exit(1);
}

if (!fs.existsSync(distDir)) fs.mkdirSync(distDir, { recursive: true });

// ── Run crx3 ─────────────────────────────────────────────────────────────────
console.log(`\nPacking CRX v${version}...`);
if (fs.existsSync(pemPath)) {
  console.log(`  Reusing existing key: dist/check.pem  (extension ID stays stable)`);
} else {
  console.log(`  Generating new private key → dist/check.pem`);
  console.log(`  ⚠️  Back up check.pem — losing it means users must reinstall on next update`);
}

const isWin   = process.platform === 'win32';
const crx3Bin = path.join(rootDir, 'node_modules', '.bin', 'crx3' + (isWin ? '.cmd' : ''));

const result = spawnSync(crx3Bin, [
  '-p', pemPath,
  '-o', crxPath,
  '-x', xmlPath,
  '--appVersion', version,
  '--crxURL', CRX_URL,
], {
  input:  fs.readFileSync(zipPath),
  shell:  isWin,
  stdio:  ['pipe', 'inherit', 'inherit'],
  cwd:    rootDir,
});

if (result.error) {
  console.error('\nFailed to run crx3:', result.error.message);
  process.exit(1);
}
if (result.status !== 0) {
  console.error(`\ncrx3 exited with code ${result.status}`);
  process.exit(1);
}

if (!fs.existsSync(crxPath)) {
  console.error('\ncrx3 ran but no .crx file was created — check output above for errors');
  process.exit(1);
}

// ── Report ───────────────────────────────────────────────────────────────────
const crxSize = (fs.statSync(crxPath).size / 1024).toFixed(1);
console.log(`\n✓ dist/check-chrome.crx       (${crxSize} KB)  ← upload to GitHub, overwrite old file`);
console.log(`✓ dist/update_manifest.xml    ← upload to GitHub, overwrite old file`);
console.log(`✓ dist/check.pem              keep private — do not commit to git!`);

const xml     = fs.readFileSync(xmlPath, 'utf8');
const idMatch = xml.match(/appid="([a-p]{32})"/);
const extId   = idMatch ? idMatch[1] : '(open dist/update_manifest.xml for appid)';

console.log(`\nExtension ID : ${extId}`);
console.log(`Version      : ${version}`);
console.log(`CRX URL      : ${CRX_URL}`);
console.log(`Manifest URL : ${MANIFEST_URL}`);
console.log(`\nTo release:`);
console.log(`  1. Upload dist/check-chrome.crx      → ${PAGES_BASE}/check-chrome.crx`);
console.log(`  2. Upload dist/update_manifest.xml   → ${PAGES_BASE}/update_manifest.xml`);
console.log(`  Chrome/Edge on managed machines will auto-update within a few hours.`);
