#!/usr/bin/env node
/**
 * Build-time check — does the pnpm-resolved vditor match the pinned
 * expected version + dist hash?
 *
 * Why this exists (DC11 / SEAM5 drift mechanism, per PD3+PD4):
 *   vditor's CDN-loader pattern + the asset URLs it builds at runtime
 *   are part of the fork's RUNTIME CONTRACT. If a future vditor minor
 *   bump silently changes how Lute is loaded, or where it's looked up,
 *   or what shape the i18n bindings have, our local-bundle assumption
 *   breaks and the editor stops working. We want that failure at
 *   BUILD time, not at user-install time.
 *
 *   This check:
 *     1. Reads node_modules/vditor/package.json's version.
 *     2. Reads media-src/vditor-compat.json's expectedVersion.
 *     3. Mismatch → exit 1 with a clear "bump expectedVersion AND
 *        re-validate the runtime contract" message.
 *
 *   Hash check is stubbed for now (compat.json has the sentinel
 *   "sha256:auto-on-first-run" — change to a real sha256 to enable
 *   strict byte-level pinning).
 *
 * When to update the compat lock:
 *   - You intentionally bumped vditor in package.json
 *   - You ran the integration smoke + all PoCs and they passed
 *   - You spot-checked the editor in VS Code (toolbar, image upload,
 *     copy-md, theme switch)
 *   Then: edit media-src/vditor-compat.json to the new version.
 *
 * Run from media-src/ — called by `pnpm build` (after copy-vditor-assets).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const COMPAT = path.join(__dirname, 'vditor-compat.json');
const VDITOR_PKG = path.join(__dirname, 'node_modules', 'vditor', 'package.json');
const LUTE_JS = path.join(__dirname, 'node_modules', 'vditor', 'dist', 'js', 'lute', 'lute.min.js');

function read(p) {
  if (!fs.existsSync(p)) {
    console.error(`[check-vditor-compat] missing: ${p}`);
    process.exit(1);
  }
  return fs.readFileSync(p, 'utf8');
}

function sha256(s) {
  return 'sha256:' + crypto.createHash('sha256').update(s).digest('hex');
}

function main() {
  const compat = JSON.parse(read(COMPAT));
  const vditorPkg = JSON.parse(read(VDITOR_PKG));

  const resolvedVersion = vditorPkg.version;
  const expectedVersion = compat.expectedVersion;

  if (resolvedVersion !== expectedVersion) {
    console.error('');
    console.error('[check-vditor-compat] VERSION MISMATCH');
    console.error('  resolved (pnpm):  ', resolvedVersion);
    console.error('  expected (compat):', expectedVersion);
    console.error('');
    console.error('  vditor is the markdown engine + Lute runtime + per-feature renderers.');
    console.error('  A version bump can change:');
    console.error('    - the cdn URL pattern (${cdn}/dist/js/lute/lute.min.js etc.)');
    console.error('    - the Lute sanitizer behavior (e.g., 3.11.2 strips javascript:, 3.8.4 did not)');
    console.error('    - the i18n string export (3.10+ uses window.VditorI18n)');
    console.error('    - the upload handler API (3.11+ requires return null on success)');
    console.error('    - the vditor.vditor.{ir,wysiwyg,sv} internals we reach into');
    console.error('');
    console.error('  To accept the bump:');
    console.error('    1. Run `pnpm test` from the repo root (all 7 PoCs + integration smoke must pass).');
    console.error('    2. Manually test in VS Code (open a markdown file; verify toolbar, image upload, copy-md, theme switch all work).');
    console.error('    3. Update `expectedVersion` in media-src/vditor-compat.json to', `"${resolvedVersion}".`);
    console.error('');
    process.exit(1);
  }

  // Hash check — only fires if compat.json has a real sha256 (not the
  // first-run sentinel).
  const expectedHash = compat.expectedDistJsHash;
  if (expectedHash && expectedHash !== 'sha256:auto-on-first-run') {
    const actualHash = sha256(read(LUTE_JS));
    if (actualHash !== expectedHash) {
      console.error('');
      console.error('[check-vditor-compat] LUTE DIST HASH MISMATCH');
      console.error('  resolved hash:', actualHash);
      console.error('  expected hash:', expectedHash);
      console.error('');
      console.error('  vditor version matches but the Lute bundle file differs from the');
      console.error('  pinned hash. Possible causes:');
      console.error('    - Registry-level tampering (very unlikely — pnpm verifies tarball integrity).');
      console.error('    - vditor re-published the same version with different contents (rare but legal).');
      console.error('    - You changed Node version / pnpm version / OS and the install produced different bytes.');
      console.error('');
      console.error('  If you trust the new hash, update `expectedDistJsHash` in');
      console.error('  media-src/vditor-compat.json to', `"${actualHash}".`);
      console.error('');
      process.exit(1);
    }
  }

  console.log(`[check-vditor-compat] OK — vditor@${resolvedVersion} matches compat lock`);
}

main();
