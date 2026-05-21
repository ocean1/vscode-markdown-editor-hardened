#!/usr/bin/env node
/**
 * PoC H5 — open-link OS-handler pivot via permissive URL
 *
 * Threat model (PRE-FORK):
 *   The webview's `fixLinkClick` intercepts every <a> click and sends
 *   `{command: 'open-link', href}` to the extension. Upstream's handler:
 *     case 'open-link': {
 *       let url = message.href
 *       if (!/^http/.test(url)) {
 *         url = NodePath.resolve(this._fsPath, '..', url)
 *       }
 *       vscode.commands.executeCommand('vscode.open', vscode.Uri.parse(url))
 *     }
 *   No scheme allowlist — anything that doesn't start with `http` gets
 *   path-resolved (broken for non-file schemes) and then passed to
 *   `vscode.open`, which dispatches to the OS handler. Real risk:
 *   `[click](file:///Applications/Calculator.app)` — OS launches Calculator
 *   (or worse: a malicious .app dropped into /tmp).
 *
 * Fork fix (C1.9 / DC6):
 *   `validateOpenLinkUrl` allowlists http/https/mailto, allows file: only
 *   if the resolved path is INSIDE a workspace folder, allows bare
 *   relative paths (resolved against the file dir, then workspace
 *   containment-checked), rejects everything else (data:, javascript:,
 *   command:, vscode:, ftp:, ...).
 *
 * Verified by:
 *   - Part B: drive validateOpenLinkUrl with a corpus of hostile + valid
 *     inputs, assert each is handled correctly.
 *   - Part C: source-grep src/extension.ts to confirm both open-link
 *     sites call validateOpenLinkUrl (the host-side gate is in place).
 */

const path = require('path');
const fs = require('fs');

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
// Post-C3.1 (DC12): the open-link wiring lives in BOTH extension.ts (where
// the panel/provider classes are) AND webview/message-dispatcher.ts
// (where the message switch lives). Source-grep both.
const SRC_FILES = [
  path.join(__dirname, '..', '..', 'src', 'extension.ts'),
  path.join(__dirname, '..', '..', 'src', 'webview', 'message-dispatcher.ts'),
];

const { validateOpenLinkUrl } = require(PATH_VALIDATION);

function partB_validatorBehavior() {
  console.log('\n[poc-h5] part B — validateOpenLinkUrl');

  const CURRENT_FILE = '/home/user/workspace/docs/note.md';
  const WS_ROOTS = ['/home/user/workspace'];

  // Rejection cases.
  const rejectCases = [
    // Forbidden schemes.
    { href: 'data:text/html,<script>alert(1)</script>',      reason: 'scheme-not-allowed' },
    { href: 'javascript:alert(1)',                           reason: 'scheme-not-allowed' },
    { href: 'command:workbench.action.terminal.new',         reason: 'scheme-not-allowed' },
    { href: 'vscode://settings',                             reason: 'scheme-not-allowed' },
    { href: 'ftp://evil/file',                               reason: 'scheme-not-allowed' },
    { href: 'ssh://evil',                                    reason: 'scheme-not-allowed' },
    // file: outside the workspace — RCE pivot territory.
    { href: 'file:///Applications/Calculator.app',           reason: 'file-outside-workspace' },
    { href: 'file:///tmp/poc.sh',                            reason: 'file-outside-workspace' },
    { href: 'file:///etc/passwd',                            reason: 'file-outside-workspace' },
    // Relative paths that escape the workspace.
    { href: '../../../tmp/poc.sh',                           reason: 'file-outside-workspace' },
    // Empty / type-confusion.
    { href: '',                                              reason: 'empty' },
    { href: null,                                            reason: 'not-string' },
    { href: undefined,                                       reason: 'not-string' },
    { href: 42,                                              reason: 'not-string' },
    // Malformed URLs that DO have an allowed scheme prefix.
    { href: 'http://[invalid',                               reason: 'malformed' },
  ];

  let failures = 0;
  for (const { href, reason } of rejectCases) {
    const result = validateOpenLinkUrl(href, CURRENT_FILE, WS_ROOTS);
    const got = result.ok ? `OK(${result.kind})` : result.reason;
    const ok = !result.ok && result.reason === reason;
    const tag = ok ? '✓' : '✗';
    const displayHref = typeof href === 'string'
      ? (href.length > 50 ? JSON.stringify(href.slice(0, 47)) + '...' : JSON.stringify(href))
      : String(href);
    console.log(`  ${tag} ${displayHref.padEnd(55)} want=${reason.padEnd(28)} got=${got}`);
    if (!ok) failures++;
  }

  // Acceptance cases.
  const acceptCases = [
    { href: 'https://example.com/page',                      kind: 'http' },
    { href: 'http://localhost:8080/dev',                     kind: 'http' },
    { href: 'mailto:user@example.com',                       kind: 'mailto' },
    { href: 'mailto:user@example.com?subject=hi',            kind: 'mailto' },
    // file: inside workspace.
    { href: 'file:///home/user/workspace/docs/other.md',     kind: 'file' },
    // Relative paths inside workspace.
    { href: './other.md',                                    kind: 'file' },
    { href: 'other.md',                                      kind: 'file' },
    { href: '../assets/image.png',                           kind: 'file' },  // workspace/assets — inside
  ];
  console.log('\n  --- valid inputs (must be accepted) ---');
  for (const { href, kind } of acceptCases) {
    const result = validateOpenLinkUrl(href, CURRENT_FILE, WS_ROOTS);
    const ok = result.ok && result.kind === kind;
    const tag = ok ? '✓' : '✗';
    const detail = result.ok ? `kind=${result.kind}` : `rejected: ${result.reason}`;
    console.log(`  ${tag} ${JSON.stringify(href).padEnd(55)} want=${kind.padEnd(8)} ${detail}`);
    if (!ok) failures++;
  }

  return { failures };
}

function partC_sourceLevelProperties() {
  console.log('\n[poc-h5] part C — source-level properties');
  const source = SRC_FILES.map((p) => {
    if (!fs.existsSync(p)) throw new Error(`not found: ${p}`);
    return fs.readFileSync(p, 'utf8');
  }).join('\n');
  const stripped = source
    .replace(/\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');

  const checks = [
    {
      name: 'validateOpenLinkUrl is imported from security/path-validation',
      pass: /import\s+\{[^}]*validateOpenLinkUrl[^}]*\}\s+from\s+['"][./]+security\/path-validation['"]/.test(stripped),
    },
    {
      name: 'validateOpenLinkUrl is called from the message dispatcher',
      pass: /validateOpenLinkUrl\s*\(/.test(stripped),
    },
    {
      name: 'no `!/^http/.test(url)` pattern (the upstream broken regex)',
      pass: !/!\s*\/\^http\/\s*\.test/.test(stripped),
    },
    {
      name: 'no NodePath.resolve into open-link (upstream\'s "relative=path" treatment)',
      pass: !/case\s+['"]open-link['"][^}]*NodePath\.resolve/.test(stripped),
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
  const partB = partB_validatorBehavior();
  const partC = partC_sourceLevelProperties();

  console.log('\n[poc-h5] summary:');
  console.log(`  part B: ${partB.failures} failure(s)`);
  console.log(`  part C: ${partC.failures} failure(s)`);

  const totalFailures = partB.failures + partC.failures;
  if (totalFailures > 0) {
    console.log(`\n[poc-h5] OVERALL: FAIL — ${totalFailures} check(s) failed`);
    process.exit(1);
  }
  console.log('\n[poc-h5] OVERALL: PASS — H5 open-link pivot closed');
  process.exit(0);
} catch (e) {
  console.error(`\n[poc-h5] ERROR: ${e.message}`);
  console.error(e.stack);
  process.exit(2);
}
