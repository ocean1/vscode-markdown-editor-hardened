# Tests

Regression tests + security PoCs for `markdown-editor-hardened`. Designed to run **without** installing the extension in VS Code — pure node + jsdom, drives the relevant artifacts (vditor/Lute, the extension's source-level properties) directly.

## Layout

- `pocs/` — security regression PoCs. One per closed audit finding. Each demonstrates the vulnerability would-be-reachable AND the fork's fix property is in place.
- `fixtures/` — large test artifacts (Lute WASM/JS, etc.). Gitignored. Tests fetch + cache on first run.
- `integration/` — wider integration tests (placeholder for T1 C1.19; not yet present).
- `run-all.js` — entry-point that runs all `pocs/*.js` and `integration/*.js`, exits non-zero on any failure.

## Run

```bash
pnpm install                     # extension-host deps (typescript, vsce, etc.)
cd tests && pnpm install         # test-runner deps (jsdom, node-fetch)
cd .. && pnpm test               # runs run-all.js
```

For a single PoC:
```bash
node tests/pocs/poc-h2-command-uri.js
```

## PoCs index

| ID | finding | PoC | status |
|----|---------|-----|--------|
| H2 | RCE via crafted markdown `command:` URI (Lute does not strip; `enableCommandUris: true` dispatched it) | `pocs/poc-h2-command-uri.js` | C1.3 (landed) |
| H3 | XSS via `customCss` raw HTML in `<style>` interpolation | `pocs/poc-h3-customcss-xss.js` | pending C1.5 |
| H4 | Upload write-anywhere via webview-supplied filename | `pocs/poc-h4-upload-traversal.js` | pending C1.8 |
| H9 | jsdelivr CDN dependency at runtime | `pocs/poc-h9-cdn-block.js` | pending C1.15 |

## PoC pattern

Each PoC has two parts:

- **Part A: vulnerability demonstration**. Shows the issue is/was reachable in the unpatched substrate (the upstream code, or the underlying library behavior the upstream code relies on). This is INVARIANT to our fork's changes — it documents the threat.
- **Part B: fork fix property**. Asserts the fork's source/runtime property that closes the issue. This is the regression gate.

If Part A starts failing (e.g., upstream Lute starts stripping `command:`), that's not a regression in our fork — it's the substrate self-correcting. The PoC logs the change but does not fail. Part B failing IS a regression: our fix has been undone or made ineffective.
