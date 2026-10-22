#!/usr/bin/env node
/**
 * Creates dist/update_manifest.xml for self-hosted (off-store) CRX deployment.
 *
 * Usage:
 *   node scripts/create-update-manifest.js <extension-id> <crx-https-url>
 *
 * Example:
 *   node scripts/create-update-manifest.js abcdefghijklmnopabcdefghijklmnop \
 *       https://updates.example.com/check/check-chrome-1.2.0.crx
 *
 * The generated update_manifest.xml is referenced by the ImmyBot script's
 * ChromeUpdateUrl / EdgeUpdateUrl parameters and by the ExtensionInstallForcelist
 * registry key.  Both Chrome and Edge accept the same manifest file.
 */

import fs   from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir   = path.join(__dirname, '..');

const extensionId = process.argv[2];
const crxUrl      = process.argv[3];

if (!extensionId || !crxUrl) {
  console.error('Usage: node scripts/create-update-manifest.js <extension-id> <crx-https-url>');
  console.error('');
  console.error('Example:');
  console.error('  node scripts/create-update-manifest.js abcdefghijklmnopabcdefghijklmnop \\');
  console.error('      https://updates.example.com/check/check-chrome-1.2.0.crx');
  process.exit(1);
}

if (!/^[a-p]{32}$/.test(extensionId)) {
  console.error(`Invalid extension ID "${extensionId}" — must be 32 lowercase letters a-p`);
  process.exit(1);
}

if (!crxUrl.startsWith('https://')) {
  console.error('CRX URL must use HTTPS — Chrome and Edge will not load CRX files over plain HTTP');
  process.exit(1);
}

// Read version from manifest.json
const manifest = JSON.parse(fs.readFileSync(path.join(rootDir, 'manifest.json'), 'utf8'));
const version  = manifest.version;

const xml = `<?xml version='1.0' encoding='UTF-8'?>
<!--
  Update manifest for self-hosted Chrome / Edge extension deployment.

  Reference this file's URL in:
    - ImmyBot script: $ChromeUpdateUrl and $EdgeUpdateUrl parameters
    - Registry policy: ExtensionInstallForcelist
        HKLM\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionSettings\\${extensionId}
        update_url = <this file's URL>

  Both Chrome and Edge can share this same manifest file.
  Update the codebase URL and version attribute each time you release a new build.
-->
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='${extensionId}'>
    <updatecheck codebase='${crxUrl}' version='${version}' />
  </app>
</gupdate>
`;

const outDir = path.join(rootDir, 'dist');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

const outPath = path.join(outDir, 'update_manifest.xml');
fs.writeFileSync(outPath, xml, 'utf8');

console.log(`\n✓ dist/update_manifest.xml created`);
console.log(`  Extension ID : ${extensionId}`);
console.log(`  CRX URL      : ${crxUrl}`);
console.log(`  Version      : ${version}`);
console.log(`\nNext steps:`);
console.log(`  1. Upload dist/check-chrome-${version}.crx  → your HTTPS host`);
console.log(`  2. Upload dist/update_manifest.xml          → your HTTPS host`);
console.log(`  3. In ImmyBot script set:`);
console.log(`       $ChromeExtensionId = '${extensionId}'`);
console.log(`       $EdgeExtensionId   = '${extensionId}'`);
console.log(`       $ChromeUpdateUrl   = '<url-to-update_manifest.xml>'`);
console.log(`       $EdgeUpdateUrl     = '<url-to-update_manifest.xml>'`);
