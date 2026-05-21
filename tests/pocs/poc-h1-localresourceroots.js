#!/usr/bin/env node
/**
 * PoC H1 — over-broad `localResourceRoots`
 *
 * Threat model (PRE-FORK):
 *   Upstream set `localResourceRoots: [Uri.file("/"), Uri.file("A:/"), ...,
 *   Uri.file("Z:/")]` — granting the webview read access to the entire local
 *   filesystem (every drive on Windows). This was a defense-in-depth weakness:
 *   currently inert (no malicious code in the bundle reads files), but
 *   COMBINED with any future webview compromise (XSS via H3, malicious vditor
 *   release via H9, etc.), this would let attacker code read arbitrary files
 *   via the webview's URI-mapping facility.
 *
 * Fork fix (C1.6 / DC3):
 *   Replaced with a scoped set: [extensionUri, ...workspace folders, current
 *   file's directory]. Implemented via `scopedLocalResourceRoots()`.
 *
 * Verified by source-level properties (no runtime test — webview options
 * only take effect inside VS Code's webview runtime):
 *   (a) no active `Uri.file("/")` or `Uri.file('/')` outside comments
 *   (b) no active A-Z drive letter enumeration (`fromCharCode(i)` loop with
 *       i in 65..90, or similar pattern)
 *   (c) `scopedLocalResourceRoots` is called from BOTH webview-options sites
 *       (EditorPanel.getWebviewOptions AND
 *        MarkdownEditorProvider.getWebviewOptions)
 *   (d) the now-dead `getFolders` static helpers are removed from both
 *       classes
 */

const fs = require('fs');
const path = require('path');

const EXTENSION_TS = path.join(__dirname, '..', '..', 'src', 'extension.ts');

function partA_sourceProperties() {
  console.log('\n[poc-h1] source-level properties — localResourceRoots scoping is in place');
  if (!fs.existsSync(EXTENSION_TS)) {
    throw new Error(`extension.ts not found at ${EXTENSION_TS}`);
  }
  const source = fs.readFileSync(EXTENSION_TS, 'utf8');
  const stripped = source
    .replace(/\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');

  const checks = [
    {
      name: 'no active Uri.file("/") (root filesystem URI)',
      pass: !/vscode\.Uri\.file\s*\(\s*["']\/["']\s*\)/.test(stripped),
    },
    {
      name: 'no A-Z drive letter enumeration via fromCharCode loop',
      pass: !/(fromCharCode\s*\(\s*i\s*\)|for\s*\(\s*let\s+i\s*=\s*65)/.test(stripped),
    },
    {
      name: 'no static getFolders() helper (dead code from the upstream pattern)',
      pass: !/getFolders\s*\(/.test(stripped),
    },
    {
      name: 'scopedLocalResourceRoots is defined',
      pass: /function\s+scopedLocalResourceRoots/.test(stripped),
    },
    {
      name: 'scopedLocalResourceRoots is called ≥2 times (both webview-options sites)',
      pass: (stripped.match(/scopedLocalResourceRoots\s*\(/g) || []).length >= 2,
    },
  ];

  let failures = 0;
  for (const c of checks) {
    const tag = c.pass ? '✓' : '✗';
    console.log(`  ${tag} ${c.name}`);
    if (!c.pass) failures++;
  }
  return { failures };
}

try {
  const { failures } = partA_sourceProperties();
  if (failures > 0) {
    console.log(`\n[poc-h1] FAIL — ${failures} check(s) failed`);
    process.exit(1);
  }
  console.log('\n[poc-h1] PASS — H1 localResourceRoots scoping is in place');
  process.exit(0);
} catch (e) {
  console.error(`\n[poc-h1] ERROR: ${e.message}`);
  console.error(e.stack);
  process.exit(2);
}
