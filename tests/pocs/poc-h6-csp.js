#!/usr/bin/env node
/**
 * PoC H6 — Content-Security-Policy on webview HTML
 *
 * Threat model (PRE-FORK):
 *   No CSP meta tag on webview HTML. With `enableScripts: true`:
 *     - any XSS bug would have unfettered fetch/exfil
 *     - inline-script injection (H3 chain) would execute
 *     - third-party compromise (e.g., a malicious vditor release on
 *       jsdelivr) would have full webview access
 *
 * Fork fix (C1.10 / DC4):
 *   `buildCspMeta(webview, nonce)` emits a strict CSP meta tag, called
 *   from both `_getHtmlForWebview` sites. Script tags are nonce-gated
 *   with a per-render `generateNonce()`.
 *
 * This PoC verifies the CSP properties at the SOURCE LEVEL (the runtime
 * effect requires the VS Code webview host — not testable in plain
 * node). Source checks:
 *   - `buildCspMeta` is defined
 *   - `generateNonce` is defined
 *   - both HTML templates call `buildCspMeta(webview, nonce)`
 *   - both HTML templates emit `<script nonce="${nonce}" ...>` (NOT a
 *     bare `<script ...>` without nonce)
 *   - the CSP directives include:
 *       default-src 'none'
 *       script-src 'nonce-${nonce}' (with the actual nonce placeholder)
 *       frame-src 'none'
 *       object-src 'none'
 *       base-uri 'none'
 *
 * A future C1.19 integration test (vditor render fidelity) will assert
 * the actual rendered HTML conforms to these properties.
 */

const path = require('path');
const fs = require('fs');

const EXTENSION_TS = path.join(__dirname, '..', '..', 'src', 'extension.ts');

function partA_sourceProperties() {
  console.log('\n[poc-h6] source-level CSP properties');
  if (!fs.existsSync(EXTENSION_TS)) {
    throw new Error(`extension.ts not found at ${EXTENSION_TS}`);
  }
  const source = fs.readFileSync(EXTENSION_TS, 'utf8');
  // Note: for CSP checks we need to keep COMMENTS stripped from
  // pattern-matching purposes (so a doc-comment containing
  // `default-src 'none'` doesn't false-pass) BUT we want to keep the
  // string literals inside template-strings — so we only strip
  // line comments + block comments outside strings.
  // For safety: use the full source for ABSENCE checks (so a comment
  // mentioning a bad pattern would FAIL the check, which is the
  // conservative direction) and use the stripped source for PRESENCE
  // checks (so a comment mentioning a good pattern doesn't fake-pass).
  const stripped = source
    .replace(/\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');

  const checks = [
    {
      name: 'buildCspMeta is defined',
      pass: /function\s+buildCspMeta\b/.test(stripped),
    },
    {
      name: 'generateNonce is defined',
      pass: /function\s+generateNonce\b/.test(stripped),
    },
    {
      name: 'buildCspMeta is called ≥2 times (both template sites)',
      pass: (stripped.match(/buildCspMeta\s*\(/g) || []).length >= 2,
    },
    {
      name: 'generateNonce is called ≥2 times (both template sites)',
      pass: (stripped.match(/generateNonce\s*\(/g) || []).length >= 2,
    },
    {
      name: '<script nonce="${nonce}" pattern present in templates',
      pass: /<script\s+nonce="\$\{nonce\}"/.test(stripped),
    },
    {
      name: 'no bare <script src=...> without nonce in templates',
      // Match `<script src=...>` that does NOT have `nonce=` between
      // `<script` and the closing `>`. The negative lookahead checks
      // that no `nonce=` appears in the attribute block.
      pass: !/<script\s+(?!nonce=)[^>]*src=/.test(stripped),
    },
    {
      name: "CSP directive: default-src 'none'",
      pass: /default-src\s+'none'/.test(stripped),
    },
    {
      name: "CSP directive: script-src includes 'nonce-${nonce}'",
      pass: /script-src[^,;]*'nonce-\$\{nonce\}'/.test(stripped),
    },
    {
      name: "CSP directive: frame-src 'none'",
      pass: /frame-src\s+'none'/.test(stripped),
    },
    {
      name: "CSP directive: object-src 'none'",
      pass: /object-src\s+'none'/.test(stripped),
    },
    {
      name: "CSP directive: base-uri 'self' (was 'none' initially; relaxed because 'none' blocked the webview's own <base href> tag, breaking vditor's content-theme CSS load chain)",
      pass: /base-uri\s+'self'/.test(stripped),
    },
    {
      name: 'meta http-equiv="Content-Security-Policy" emitted',
      pass: /meta\s+http-equiv="Content-Security-Policy"/.test(stripped),
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
  const partA = partA_sourceProperties();
  if (partA.failures > 0) {
    console.log(`\n[poc-h6] FAIL — ${partA.failures} check(s) failed`);
    process.exit(1);
  }
  console.log('\n[poc-h6] PASS — CSP is in place at the source level');
  process.exit(0);
} catch (e) {
  console.error(`\n[poc-h6] ERROR: ${e.message}`);
  console.error(e.stack);
  process.exit(2);
}
