# Markdown Editor (Hardened)

A security-hardened fork of [`zaaack/vscode-markdown-editor`](https://github.com/zaaack/vscode-markdown-editor) — a WYSIWYG markdown editor for VS Code powered by [vditor](https://github.com/Vanessa219/vditor).

## What's different from upstream

This fork addresses 7 security issues identified in a code audit of upstream `0.1.13` / `0.1.14`. The hardening is rolling out across tiers:

- **T0** (current): repo identity, defensive stub for the `customCss` XSS vector (full redesign in T1).
- **T1** (in progress): remove `enableCommandUris: true` (closes RCE via crafted markdown `command:` URIs), drop `customCss` raw-HTML injection, scope `localResourceRoots`, add Content-Security-Policy to the webview, validate `upload` filename against path traversal, allow-list `open-link` URL schemes, bump vditor `3.8.4` → `3.11.2`, bundle vditor's Lute markdown engine locally (drop `cdn.jsdelivr.net` runtime dependency), merge selected upstream PRs (#151 CI fix, #153 find widget, #154 auto-focus, #157 line numbers).
- **T2**: drop `@testing-library` from webview bundle, full CI, `SECURITY.md` expansion, regression test suite.
- **T3**: refactor — consolidate `EditorPanel` and `MarkdownEditorProvider` (currently ~250 LoC of duplicated message handling).

See [`SECURITY.md`](SECURITY.md) for the threat model and per-issue status.

## Upstream contribution

Each independent hardening fix is sent back to upstream as a separate PR. The fork is not intended to permanently replace upstream — only to ship the fixes immediately while upstream considers them.

Open upstream PRs from this fork (will populate as T1 lands):
- TBD

## Install

This fork is not yet published to the VS Code Marketplace. To install locally:

```bash
git clone https://github.com/ocean1/vscode-markdown-editor-hardened.git
cd vscode-markdown-editor-hardened
pnpm install                  # extension-host deps
cd media-src && pnpm install  # webview deps
cd .. && pnpm pub             # builds + packages .vsix
code --install-extension markdown-editor-hardened-*.vsix
```

Note: at T0, the build outputs (`out/extension.js`, `media/dist/main.js`) are still upstream's — you need to rebuild after install. The bundled output will be regenerated in T1 (C1.13).

## Migration from upstream

If you were using `zaaack.markdown-editor`:

- This fork uses a **different extension ID** (`ocean1.markdown-editor-hardened`). Both can be installed side-by-side. Uninstall upstream once you've confirmed the fork works for your use case.
- **Settings do not migrate automatically.** The settings keys changed from `markdown-editor.*` to `markdown-editor-hardened.*`. The `markdown-editor.customCss` setting is preserved in this fork's manifest for migration honesty (so VS Code does not warn about an unknown setting), but its value is **ignored at runtime** — a hostile workspace's `customCss` cannot affect the fork. The full redesign of CSS customization (workspace-relative paths only, no inline HTML injection) lands in T1.
- **Keybinding preserved**: `cmd+shift+alt+m` (Mac) / `ctrl+shift+alt+m` (others). Command name changed from `markdown-editor.openEditor` to `markdown-editor-hardened.openEditor` but the shortcut is the same.

## Acknowledgement

- [zaaack](https://github.com/zaaack) — original author of `vscode-markdown-editor`
- [Vanessa219](https://github.com/Vanessa219) — author of [vditor](https://github.com/Vanessa219/vditor)
- contributors to upstream PRs we're merging: hackarada (#142), LeonardoRick (#153, #154), asalcedo29 (#157), mrsekut (#151)

## License

MIT — same as upstream.
