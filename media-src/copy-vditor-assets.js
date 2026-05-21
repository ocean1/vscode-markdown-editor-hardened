#!/usr/bin/env node
/**
 * Copy vditor's runtime assets (dist/js, dist/css, dist/images) into
 * `../media/vditor/` so the webview can load them via the local
 * extensionUri instead of jsdelivr.
 *
 * SECURITY (DC7 — closes H9, "jsdelivr CDN dependency at runtime"):
 *   Without this step, vditor's runtime asset loader (driven by the
 *   `cdn` option) fetches Lute, icons, and per-feature renderers
 *   (mermaid, echarts, katex, etc.) from
 *   `https://cdn.jsdelivr.net/npm/vditor@<version>/dist/...`. A
 *   compromised jsdelivr → arbitrary WASM/JS in the webview =
 *   webview RCE.
 *
 *   With this step + the host's `cdn` option pointing to the local
 *   media/vditor URL, all of vditor's runtime asset loads stay
 *   within the webview's own origin (cspSource). CSP's connect-src +
 *   script-src can drop the jsdelivr allowlist entry.
 *
 * Size cost: copying the full vditor/dist/js/ subtree adds ~20MB to
 * the extension package. This is the tradeoff for offline + supply-chain
 * safety. Scratchpad I9 tracks the option to ship a slimmer variant
 * (lute + i18n + icons only; ~4MB) if size matters.
 *
 * Source:  node_modules/vditor/dist/{js,css,images,index.css}
 * Dest:    ../media/vditor/{js,css,images,index.css}
 *
 * Run from media-src/ as part of `pnpm build`.
 */

const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, 'node_modules', 'vditor', 'dist');
// vditor's runtime loader builds asset URLs as `${cdn}/dist/...`. To
// match that pattern with our local-bundle, the destination IS
// `media/vditor/dist/...`. The host sets `window.__vditorCdn` to the
// webview-URI of `media/vditor`; vditor then constructs e.g.
// `<webview-uri>/media/vditor/dist/js/lute/lute.min.js` which maps
// cleanly to the copied file on disk.
const DST = path.join(__dirname, '..', 'media', 'vditor', 'dist');

// Subset of vditor/dist/ to copy. We include js/ (all renderers; full
// feature parity with the CDN), css/, images/, and index.css.
// EXCLUDED: ts/ (sources), types/ (TS types), *.d.ts, *.js / *.min.js
// in the root (those are the entrypoint files we already bundle via
// esbuild). The webview's entry is media/dist/main.js; vditor's own
// index.js is NOT used at runtime.
const COPY_LIST = [
  'js',
  'css',
  'images',
  'index.css',
];

function rmrf(p) {
  if (!fs.existsSync(p)) return;
  const st = fs.statSync(p);
  if (st.isDirectory()) {
    for (const ent of fs.readdirSync(p)) rmrf(path.join(p, ent));
    fs.rmdirSync(p);
  } else {
    fs.unlinkSync(p);
  }
}

function copyRecursive(src, dst) {
  const st = fs.statSync(src);
  if (st.isDirectory()) {
    if (!fs.existsSync(dst)) fs.mkdirSync(dst, { recursive: true });
    for (const ent of fs.readdirSync(src)) {
      copyRecursive(path.join(src, ent), path.join(dst, ent));
    }
  } else {
    fs.copyFileSync(src, dst);
  }
}

function main() {
  if (!fs.existsSync(SRC)) {
    console.error(`[copy-vditor-assets] source not found: ${SRC}`);
    console.error('  Did you run `pnpm install` in media-src/?');
    process.exit(1);
  }
  console.log(`[copy-vditor-assets] cleaning ${DST}`);
  rmrf(DST);
  fs.mkdirSync(DST, { recursive: true });
  for (const entry of COPY_LIST) {
    const src = path.join(SRC, entry);
    const dst = path.join(DST, entry);
    if (!fs.existsSync(src)) {
      console.warn(`[copy-vditor-assets] WARN: ${src} not present, skipping`);
      continue;
    }
    console.log(`[copy-vditor-assets] copy ${entry}`);
    copyRecursive(src, dst);
  }
  console.log(`[copy-vditor-assets] done`);
}

main();
