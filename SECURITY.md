# Security policy — `markdown-editor-hardened`

## Status

This is **T0 foundation** of a multi-tier security hardening of upstream
[`zaaack/vscode-markdown-editor`](https://github.com/zaaack/vscode-markdown-editor).
T0 lands the fork scaffolding (renames, repo identity, this SECURITY.md
placeholder, and a single defensive stub closing the `customCss` XSS vector
ahead of its full redesign in T1).

The full hardening plan (T1: 6 security fixes + CSP + vditor bump + local Lute
bundle, T2: docs + CI, T3: refactor) is rolling out across subsequent commits.
This file will be expanded as fixes land.

Until T1 completes, this fork is **not** yet a full replacement for upstream
from a security standpoint — only the `customCss` `<style>`-breakout vector is
closed at T0. The other vectors (command-URI RCE, broad localResourceRoots,
no-CSP webview, upload path traversal, open-link URL pivot, jsdelivr CDN
dependency) are still present and will be closed across T1.

## Threat model the fork addresses

The audit that motivated this fork found 7 issues in upstream 0.1.13 (the
currently-published Marketplace version, identical to 0.1.14 + .vsix-built
source per byte-for-byte diff). Severity ratings reflect a threat model of
"user has the extension installed and opens a markdown file from an untrusted
source (downloaded, attachment, cloned repo)":

| # | Class | Severity | Status (this fork) | Status (upstream) |
|---|-------|----------|--------------------|--------------------|
| H2 | RCE via crafted markdown `command:` URI (`enableCommandUris: true` + Lute does not strip `command:` schemes) | high | T1 / C1.2 (open) | unfixed |
| H3 | XSS via `customCss` raw HTML injection through `<style>` interpolation (workspace-trust bypass) | high | T0 / defensive stub (active) → T1 / C1.4 (full redesign) | unfixed |
| H4 | Write-anywhere primitive in `upload` message handler (webview-supplied filename, no path-traversal validation) | medium (high given webview compromise) | T1 / C1.7 (open) | unfixed |
| H5 | OS-handler pivot via `open-link` with no scheme allowlist | medium | T1 / C1.9 (open) | unfixed |
| H6 | No Content-Security-Policy on webview HTML (defense-in-depth gap) | medium | T1 / C1.10 (open) | unfixed |
| H9 | jsdelivr CDN dependency at runtime (every editor open fetches vditor's Lute from jsdelivr) | medium (supply-chain) | T1 / C1.14 (open) | unfixed |
| H1 | Over-broad `localResourceRoots: [/, A:/..Z:/]` (currently inert; widens blast radius of webview compromise) | low | T1 / C1.6 (open) | unfixed |

Reachability of H2 was confirmed by a programmatic Lute test (vditor 3.8.4 +
3.11.2 both render `[click](command:foo)` as `<a href="command:foo">click</a>`
verbatim, with `SetSanitize(true)` — the default). The H12 test will be
shipped as `tests/poc-h2-command-uri.js` in C1.3.

## Disclosure / responsible-disclosure

If you find a new issue, please open a private security advisory on
[github.com/ocean1/vscode-markdown-editor-hardened](https://github.com/ocean1/vscode-markdown-editor-hardened/security/advisories/new)
rather than a public issue.

For issues that also affect upstream, we will coordinate disclosure with
[zaaack](https://github.com/zaaack) — our hybrid posture sends fixes back
upstream as separate PRs alongside landing them here.

## Audit trail

The security audit that produced this fork is documented in the upstream review
notes (held privately for now). Each T1 commit will reference the relevant
finding ID (H1-H9) in its commit body, and ship a regression PoC where
applicable.
