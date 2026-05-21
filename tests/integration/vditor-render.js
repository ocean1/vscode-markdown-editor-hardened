#!/usr/bin/env node
/**
 * Integration smoke test — vditor (Lute) render fidelity
 *
 * Drives the vditor's bundled Lute markdown engine (whose JS is in
 * media/vditor/dist/js/lute/lute.min.js after C1.14) with a
 * representative markdown sample, asserts the rendered HTML contains
 * the expected element shapes.
 *
 * Purpose:
 *   - INV1 (no editing-fidelity regression): catches vditor-bump-time
 *     breakages where the markdown engine starts producing different
 *     HTML (toolbar UI breakages can only be caught in VS Code).
 *   - Defense against future vditor compromises: a malicious vditor
 *     release that mangles markdown rendering (e.g., to inject ads,
 *     to drop sanitization) would show up here.
 *
 * Coverage:
 *   - headings (h1-h3)
 *   - lists (ul, ol)
 *   - code blocks (fenced)
 *   - inline code
 *   - tables
 *   - blockquotes
 *   - bold / italic
 *   - links (http, mailto, relative)
 *   - images
 *   - paragraphs
 *
 * What this test does NOT cover:
 *   - In-VS-Code UI (toolbar, gutter, focus behavior) — requires actual
 *     VS Code webview runtime.
 *   - CSP enforcement at runtime — the source-level PoC H6 handles that.
 *   - Per-render correctness (e.g., the line-number-gutter mapping
 *     accuracy from C1.18) — that's a runtime-only behavior.
 */

const path = require('path');
const fs = require('fs');
const { JSDOM } = require('jsdom');

const LUTE_LOCAL = path.join(
  __dirname, '..', '..', 'media', 'vditor', 'dist', 'js', 'lute', 'lute.min.js'
);

if (!fs.existsSync(LUTE_LOCAL)) {
  console.error(`[vditor-render] Lute bundle not found at ${LUTE_LOCAL}`);
  console.error('  Did you run `cd media-src && pnpm build`?');
  process.exit(2);
}

const SAMPLE_MD = `---
title: Sample
date: 2026-05-21
---

# Heading 1

A regular paragraph with **bold** and *italic* and \`inline code\`.

## Heading 2

- List item 1
- List item 2
  - Nested item

### Heading 3

1. Ordered item 1
2. Ordered item 2

> A blockquote.
> Second line of the quote.

\`\`\`python
def hello():
    print("world")
\`\`\`

| Col A | Col B |
|-------|-------|
| 1     | 2     |
| 3     | 4     |

[A link](https://example.com)
[Email link](mailto:user@example.com)
[Relative link](./other.md)

![alt text](image.png)
`;

function loadLute() {
  const luteJs = fs.readFileSync(LUTE_LOCAL, 'utf8');
  const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
    runScripts: 'dangerously',
    resources: 'usable',
  });
  // vditor 3.11+'s Lute references TextDecoder/TextEncoder/crypto/fetch
  // for its Go-WASM-style runtime. JSDOM exposes some but not all in
  // the eval context — polyfill from node's globals so the script
  // initializes cleanly.
  dom.window.TextDecoder = TextDecoder;
  dom.window.TextEncoder = TextEncoder;
  dom.window.crypto = require('crypto').webcrypto;
  if (typeof dom.window.fetch === 'undefined') {
    // Lute doesn't actually fetch at init in the local-bundle path, but
    // the runtime expects fetch to exist as a global. Stub it.
    dom.window.fetch = () => Promise.reject(new Error('fetch stub'));
  }
  dom.window.eval(luteJs);
  if (typeof dom.window.Lute === 'undefined') {
    throw new Error('Lute global not defined after script load');
  }
  return dom.window.Lute;
}

function main() {
  console.log('[vditor-render] loading Lute from local bundle');
  const Lute = loadLute();
  const lute = Lute.New();
  lute.SetSanitize(true);
  lute.SetGFMTable(true);
  lute.SetGFMTaskListItem(true);

  console.log('[vditor-render] rendering SAMPLE_MD');
  const rendered = lute.Md2HTML(SAMPLE_MD);

  // Print a snippet for human eyeball reference.
  console.log('\n--- rendered HTML (first 600 chars) ---');
  console.log(rendered.slice(0, 600));
  console.log('--- end snippet ---\n');

  const checks = [
    { name: 'h1 rendered',                      pass: /<h1[^>]*>Heading 1<\/h1>/.test(rendered) },
    { name: 'h2 rendered',                      pass: /<h2[^>]*>Heading 2<\/h2>/.test(rendered) },
    { name: 'h3 rendered',                      pass: /<h3[^>]*>Heading 3<\/h3>/.test(rendered) },
    { name: 'paragraph with bold',              pass: /<strong>bold<\/strong>/.test(rendered) },
    { name: 'paragraph with italic',            pass: /<em>italic<\/em>/.test(rendered) },
    { name: 'inline code rendered',             pass: /<code>inline code<\/code>/.test(rendered) },
    { name: 'unordered list',                   pass: /<ul[^>]*>[\s\S]*<li[^>]*>List item 1<\/li>/.test(rendered) },
    { name: 'nested list item',                 pass: /Nested item/.test(rendered) && /<ul[^>]*>[\s\S]*<ul[^>]*>/.test(rendered) },
    { name: 'ordered list',                     pass: /<ol[^>]*>[\s\S]*<li[^>]*>Ordered item 1<\/li>/.test(rendered) },
    { name: 'blockquote',                       pass: /<blockquote[^>]*>[\s\S]*A blockquote\./.test(rendered) },
    { name: 'fenced code block (python)',       pass: /<pre[^>]*><code[^>]*>def hello\(\):/.test(rendered) },
    { name: 'table renders',                    pass: /<table[^>]*>[\s\S]*<th[^>]*>Col A<\/th>/.test(rendered) },
    { name: 'table data cells',                 pass: /<td[^>]*>1<\/td>/.test(rendered) },
    { name: 'https link rendered',              pass: /<a href="https:\/\/example\.com">A link<\/a>/.test(rendered) },
    { name: 'mailto link rendered',             pass: /<a href="mailto:user@example\.com">Email link<\/a>/.test(rendered) },
    { name: 'relative link rendered',           pass: /<a href="\.\/other\.md">Relative link<\/a>/.test(rendered) },
    { name: 'image rendered',                   pass: /<img[^>]*src="image\.png"[^>]*alt="alt text"/.test(rendered) },
  ];

  let failures = 0;
  console.log('[vditor-render] checks:');
  for (const c of checks) {
    const tag = c.pass ? '✓' : '✗';
    console.log(`  ${tag} ${c.name}`);
    if (!c.pass) failures++;
  }

  if (failures > 0) {
    console.log(`\n[vditor-render] FAIL — ${failures}/${checks.length} check(s) failed`);
    process.exit(1);
  }
  console.log(`\n[vditor-render] PASS — all ${checks.length} render checks succeeded`);
  process.exit(0);
}

main();
