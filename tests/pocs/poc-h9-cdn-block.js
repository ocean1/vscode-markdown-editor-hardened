#!/usr/bin/env node
/**
 * PoC H9 — jsdelivr CDN dependency at runtime
 *
 * Threat model (PRE-FORK):
 *   Upstream's webview fetched vditor's Lute markdown engine + per-feature
 *   renderers from https://cdn.jsdelivr.net/npm/vditor@... on every open.
 *   Supply-chain risk + light telemetry signal + offline-broken.
 *
 * Fork fix (C1.14 / DC7):
 *   - Build-time copy of vditor/dist/{js,css,images} → media/vditor/dist/
 *     (media-src/copy-vditor-assets.js runs as part of pnpm build)
 *   - Host emits `<script>window.__vditorCdn="..."</script>` pointing at
 *     the local media/vditor URL
 *   - Webview reads __vditorCdn and passes it as Vditor.cdn option
 *   - CSP no longer allowlists cdn.jsdelivr.net (strict same-origin)
 *
 * Verified by source-level properties:
 *   (a) media/vditor/dist/js/lute/lute.min.js exists (local copy was
 *       made; this is the file vditor would otherwise fetch from CDN)
 *   (b) src/extension.ts emits `window.__vditorCdn` (the host→webview
 *       channel is in place)
 *   (c) buildCspMeta no longer contains jsdelivr (CSP tightened)
 *   (d) media-src/src/main.ts reads window.__vditorCdn (the webview
 *       picks up the local URL)
 *   (e) media-src/copy-vditor-assets.js exists (the build step)
 *   (f) media-src/package.json's build script invokes the copy step
 */

const fs = require('fs');
const path = require('path');

const FORK_ROOT = path.join(__dirname, '..', '..');
const EXTENSION_TS = path.join(FORK_ROOT, 'src', 'extension.ts');
const MAIN_TS = path.join(FORK_ROOT, 'media-src', 'src', 'main.ts');
const COPY_SCRIPT = path.join(FORK_ROOT, 'media-src', 'copy-vditor-assets.js');
const MEDIA_SRC_PKG = path.join(FORK_ROOT, 'media-src', 'package.json');
const LUTE_LOCAL = path.join(FORK_ROOT, 'media', 'vditor', 'dist', 'js', 'lute', 'lute.min.js');

function read(p) {
  if (!fs.existsSync(p)) throw new Error(`not found: ${p}`);
  return fs.readFileSync(p, 'utf8');
}
function stripComments(src) {
  return src.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
}

const checks = [
  {
    name: 'media/vditor/dist/js/lute/lute.min.js exists (local Lute bundled)',
    pass: () => fs.existsSync(LUTE_LOCAL) && fs.statSync(LUTE_LOCAL).size > 1_000_000,
  },
  {
    name: 'media-src/copy-vditor-assets.js exists (build step)',
    pass: () => fs.existsSync(COPY_SCRIPT),
  },
  {
    name: 'media-src/package.json build script calls copy-vditor-assets',
    pass: () => {
      const pkg = JSON.parse(read(MEDIA_SRC_PKG));
      return /copy-vditor-assets\.js/.test(pkg.scripts?.build || '');
    },
  },
  {
    name: 'src/extension.ts emits window.__vditorCdn',
    pass: () => /window\.__vditorCdn\s*=/.test(stripComments(read(EXTENSION_TS))),
  },
  {
    name: 'src/extension.ts: buildCspMeta does NOT allowlist jsdelivr',
    pass: () => {
      const src = stripComments(read(EXTENSION_TS));
      // Find the buildCspMeta function body and verify no jsdelivr.
      const m = src.match(/function\s+buildCspMeta[\s\S]*?\n\}/);
      if (!m) return false;
      return !/jsdelivr/.test(m[0]);
    },
  },
  {
    name: 'media-src/src/main.ts reads window.__vditorCdn',
    pass: () => /__vditorCdn/.test(stripComments(read(MAIN_TS))),
  },
  {
    name: 'media-src/src/main.ts passes cdn option to Vditor constructor',
    pass: () => {
      const src = stripComments(read(MAIN_TS));
      // Look for `cdn,` (shorthand) or `cdn:` inside a Vditor constructor block.
      return /new\s+Vditor\s*\([^)]*[\s\S]*?\bcdn\b/.test(src);
    },
  },
];

let failures = 0;
console.log('[poc-h9] source-level properties — jsdelivr CDN dependency closed');
for (const c of checks) {
  let ok;
  try { ok = c.pass(); } catch (e) { ok = false; console.error(`  error in ${c.name}: ${e.message}`); }
  const tag = ok ? '✓' : '✗';
  console.log(`  ${tag} ${c.name}`);
  if (!ok) failures++;
}

if (failures > 0) {
  console.log(`\n[poc-h9] FAIL — ${failures} check(s) failed`);
  process.exit(1);
}
console.log('\n[poc-h9] PASS — H9 CDN dependency closed');
process.exit(0);
