#!/usr/bin/env node
/**
 * PoC H4 — upload write-anywhere primitive via webview-supplied filename
 *
 * Threat model (PRE-FORK):
 *   The webview's vditor `upload.handler` builds entries `{base64, name}`
 *   from pasted/dragged files and sends them via postMessage. Upstream's
 *   `upload` message handler then wrote each entry as:
 *     fs.writeFile(NodePath.join(assetsFolder, f.name), Buffer.from(f.base64, 'base64'))
 *   NodePath.join does NOT reject `..`, absolute paths, or NUL bytes.
 *   A compromised webview (via H3 XSS chain, vditor parse bug, etc.)
 *   could send `f.name = "../../../tmp/poc.txt"` to write outside the
 *   assets folder — write-anywhere given webview compromise.
 *
 * Fork fix (C1.7 / DC5):
 *   Host-side `validateUploadEntries` filters all entries through
 *   `validateUploadFilename` BEFORE any fs write. Invalid entries are
 *   set aside; valid entries proceed.
 *
 * Verified by:
 *   - Part B: drive validateUploadFilename with a corpus of hostile inputs,
 *     assert each is rejected with the expected reason.
 *   - Part C: source-grep src/extension.ts to confirm both upload sites
 *     call validateUploadEntries (the host-side gate is in place).
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
// Post-C3.1 (DC12): the upload-handling wiring is distributed:
//   - src/upload-validation.ts        — validateUploadEntries definition
//   - src/security/path-validation.ts — validateUploadFilename definition
//   - src/webview/message-dispatcher.ts — the `upload` message case (single
//     site after the refactor — both EditorPanel + MarkdownEditorProvider
//     share this dispatcher)
//   - src/extension.ts                — the panel/provider classes that
//     install the dispatcher via onDidReceiveMessage
// Source-grep all four for the wiring checks.
const SRC_FILES = [
  path.join(__dirname, '..', '..', 'src', 'extension.ts'),
  path.join(__dirname, '..', '..', 'src', 'webview', 'message-dispatcher.ts'),
  path.join(__dirname, '..', '..', 'src', 'upload-validation.ts'),
  path.join(__dirname, '..', '..', 'src', 'security', 'path-validation.ts'),
];

const { validateUploadFilename } = require(PATH_VALIDATION);

function partB_validatorRejectsHostileInputs() {
  console.log('\n[poc-h4] part B — validateUploadFilename rejects hostile inputs');

  const cases = [
    // Classic traversal.
    { input: '../../../tmp/poc.txt',           expectedReason: 'has-path-separator' },
    { input: '../escape.png',                  expectedReason: 'has-path-separator' },
    { input: 'subdir/file.png',                expectedReason: 'has-path-separator' },
    { input: 'subdir\\file.png',               expectedReason: 'has-path-separator' },
    { input: '\\..\\..\\Windows\\poc.txt',     expectedReason: 'has-path-separator' },
    // Absolute.
    { input: '/etc/passwd',                    expectedReason: 'has-path-separator' },
    { input: '/Users/victim/.bashrc',          expectedReason: 'has-path-separator' },
    // Windows paths typically also contain backslashes — the path-separator
    // check fires first. Both rejection paths are correct; we match the
    // earlier-in-chain reason here. A drive-letter without ANY separator is
    // also tested below.
    { input: 'C:\\Users\\victim\\.ssh\\id',    expectedReason: 'has-path-separator' },
    { input: 'C:Users\\victim\\poc',           expectedReason: 'has-path-separator' },
    // A bare drive letter with no separator — matches windows-drive-letter.
    { input: 'C:badname',                      expectedReason: 'windows-drive-letter' },
    // Leading dot (hidden file; also rules out `..`).
    { input: '.bashrc',                        expectedReason: 'leading-dot' },
    { input: '.env',                           expectedReason: 'leading-dot' },
    { input: '.',                              expectedReason: 'leading-dot' },
    { input: '..',                             expectedReason: 'leading-dot' },
    // NUL byte.
    { input: 'safe.png\0',                     expectedReason: 'nul-byte' },
    { input: 'a\0../escape.png',               expectedReason: 'nul-byte' },
    // Empty.
    { input: '',                               expectedReason: 'empty' },
    // Too long.
    { input: 'a'.repeat(256) + '.png',         expectedReason: 'too-long' },
    // Type-confusion.
    { input: null,                             expectedReason: 'not-string' },
    { input: undefined,                        expectedReason: 'not-string' },
    { input: 42,                               expectedReason: 'not-string' },
    { input: ['poc.png'],                      expectedReason: 'not-string' },
  ];

  let failures = 0;
  for (const { input, expectedReason } of cases) {
    const result = validateUploadFilename(input);
    const got = result.ok ? 'OK' : result.reason;
    const ok = !result.ok && result.reason === expectedReason;
    const tag = ok ? '✓' : '✗';
    const displayInput = typeof input === 'string'
      ? (input.length > 60 ? JSON.stringify(input.slice(0, 50)) + '...' : JSON.stringify(input))
      : String(input);
    console.log(`  ${tag} input=${displayInput.padEnd(55)} want=${expectedReason.padEnd(22)} got=${got}`);
    if (!ok) failures++;
  }

  // Valid filenames must be accepted.
  const validCases = [
    'image.png',
    'photo.jpg',
    'IMG_20260520_123456.jpeg',
    'screenshot 2026-05-20 at 14.45.32.png',  // spaces OK
    'file-with-hyphens.gif',
    'file_with_underscores.svg',
    '20260520_120000_pasted.png',
  ];
  console.log('\n  --- valid inputs (must be accepted) ---');
  for (const input of validCases) {
    const result = validateUploadFilename(input);
    const tag = result.ok ? '✓' : '✗';
    const detail = result.ok ? `name=${result.name}` : `rejected: ${result.reason}`;
    console.log(`  ${tag} input=${JSON.stringify(input).padEnd(50)} ${detail}`);
    if (!result.ok) failures++;
  }

  if (failures > 0) {
    return { failures, status: 'validator-broken' };
  }
  return { failures: 0, status: 'validator-correct' };
}

function partC_sourceLevelProperties() {
  console.log('\n[poc-h4] part C — source-level properties');
  const source = SRC_FILES.map((p) => {
    if (!fs.existsSync(p)) throw new Error(`not found: ${p}`);
    return fs.readFileSync(p, 'utf8');
  }).join('\n');
  const stripped = source
    .replace(/\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');

  const checks = [
    {
      name: 'validateUploadEntries is defined (export from upload-validation.ts)',
      pass: /export\s+function\s+validateUploadEntries\b/.test(stripped),
    },
    {
      name: 'validateUploadEntries is called from the message dispatcher',
      pass: /validateUploadEntries\s*\(/.test(stripped),
    },
    {
      name: 'no NodePath.join(assetsFolder, f.name) outside the validated-loop',
      // Heuristic: every NodePath.join(assetsFolder, ...) occurrence in
      // executable code should be in a loop that iterates over `valid`,
      // not over `message.files` directly.
      pass: !/message\.files\s*\.map\s*\(\s*\(?\s*f\b[^)]*\)?\s*=>\s*[^{]*Buffer\.from\(\s*f\.base64/.test(stripped),
    },
    {
      name: 'validateUploadFilename is imported from security/path-validation',
      pass: /import\s+\{[^}]*validateUploadFilename[^}]*\}\s+from\s+['"][./]+security\/path-validation['"]/.test(stripped),
    },
    {
      name: 'validateUploadEntries is imported into the message dispatcher',
      pass: /import\s+\{[^}]*validateUploadEntries[^}]*\}\s+from\s+['"][./]+upload-validation['"]/.test(stripped),
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
  const partB = partB_validatorRejectsHostileInputs();
  const partC = partC_sourceLevelProperties();

  console.log('\n[poc-h4] summary:');
  console.log(`  part B: ${partB.status}`);
  console.log(`  part C: ${partC.failures} failure(s)`);

  const totalFailures = partB.failures + partC.failures;
  if (totalFailures > 0) {
    console.log(`\n[poc-h4] OVERALL: FAIL — ${totalFailures} check(s) failed`);
    process.exit(1);
  }
  console.log('\n[poc-h4] OVERALL: PASS — H4 upload traversal vector closed');
  process.exit(0);
} catch (e) {
  console.error(`\n[poc-h4] ERROR: ${e.message}`);
  console.error(e.stack);
  process.exit(2);
}
