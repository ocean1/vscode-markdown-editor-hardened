/**
 * Pure path-validation utilities used by the extension's webview-side glue.
 *
 * Kept in a separate module so it can be unit-tested without the `vscode`
 * module (which only loads inside the VS Code runtime). The tests in
 * `tests/pocs/*` drive these functions directly with hostile inputs.
 *
 * Each function is FAIL-CLOSED: any invalid input returns a sentinel
 * (null / false / "" / never the input itself). The extension's glue
 * code in `src/extension.ts` then treats null/false as "do nothing"
 * rather than "use the dangerous input."
 */

import * as NodePath from 'path'

/**
 * Reasons a candidate workspace-relative path can be rejected. Returned
 * by `validateWorkspaceRelativePath` for test assertion; the extension
 * glue ignores the reason and just treats any non-OK result as null.
 */
export type PathRejectReason =
  | 'empty'
  | 'not-string'
  | 'url-scheme'
  | 'protocol-relative'
  | 'absolute-posix'
  | 'absolute-windows'
  | 'nul-byte'
  | 'wrong-extension'
  | 'escapes-workspace'

export interface PathValidationResult {
  ok: true
  resolved: string  // absolute path inside the workspace root
}

export interface PathValidationFailure {
  ok: false
  reason: PathRejectReason
}

/**
 * Validate a candidate workspace-relative path. Returns `{ok: true, resolved}`
 * if the path is a clean workspace-relative file with the required extension,
 * else `{ok: false, reason}` naming the first failed check.
 *
 * @param raw           the user-supplied value (from VS Code settings)
 * @param workspaceRoot absolute path to the workspace root the path is
 *                      relative to
 * @param requiredExt   extension the path must end with, lowercase including
 *                      the dot (e.g. ".css"). Case-insensitive match against
 *                      the input.
 */
export function validateWorkspaceRelativePath(
  raw: unknown,
  workspaceRoot: string,
  requiredExt: string
): PathValidationResult | PathValidationFailure {
  if (typeof raw !== 'string') return { ok: false, reason: 'not-string' }
  const setting = raw.trim()
  if (setting === '') return { ok: false, reason: 'empty' }

  // Reject NUL bytes first (defense against C-string-truncation-style bypass
  // where a downstream consumer might truncate at NUL — we want to reject
  // BEFORE any further processing reads only the prefix).
  if (setting.includes('\0')) return { ok: false, reason: 'nul-byte' }

  // Reject absolute Windows paths (drive letters). Done BEFORE the URL-scheme
  // check because a single letter + colon (e.g. `C:`) syntactically matches
  // RFC 3986 scheme grammar, and we want the more user-friendly reason here.
  if (/^[A-Za-z]:[\\/]/.test(setting)) return { ok: false, reason: 'absolute-windows' }

  // Reject URL-shaped values (any scheme + colon).
  // Pattern: ASCII letter followed by ≥1 of [A-Za-z0-9+.-] then colon.
  // Note: scheme syntax in RFC 3986 is letter + [a-zA-Z0-9+.-]*, but we
  // require ≥1 follow-up char so a bare drive letter (`C:`) without slash
  // doesn't match here — those should have been caught by the Windows check
  // above when they're paths. A bare `C:` without slash is still rejected
  // (matches this regex too); the choice of reason is arbitrary.
  // Blocks data:, javascript:, https:, file:, ftp:, vscode:, etc.
  if (/^[a-zA-Z][a-zA-Z0-9+.\-]+:/.test(setting)) return { ok: false, reason: 'url-scheme' }

  // Protocol-relative URL.
  if (setting.startsWith('//')) return { ok: false, reason: 'protocol-relative' }

  // Reject absolute POSIX paths.
  if (setting.startsWith('/')) return { ok: false, reason: 'absolute-posix' }

  // Extension check (case-insensitive). Must match exactly the requiredExt.
  if (!setting.toLowerCase().endsWith(requiredExt.toLowerCase())) {
    return { ok: false, reason: 'wrong-extension' }
  }

  // Resolve against workspaceRoot, then ensure the result is strictly inside.
  // `NodePath.relative(wsRoot, resolved)` returns "" if equal, "../..." if
  // outside, an absolute path if on a different drive (Windows), or a
  // simple relative path if inside.
  const resolved = NodePath.resolve(workspaceRoot, setting)
  const rel = NodePath.relative(workspaceRoot, resolved)
  if (rel === '' || rel.startsWith('..') || NodePath.isAbsolute(rel)) {
    return { ok: false, reason: 'escapes-workspace' }
  }

  return { ok: true, resolved }
}

/**
 * Validate a candidate upload filename — used by the `upload` message handler
 * in `src/extension.ts` (C1.7 — DC5 / H4).
 *
 * Rejects anything that is not a plain basename (no directory parts), or
 * that contains characters that have historically been used to escape
 * filename-only contexts.
 */
export function validateUploadFilename(raw: unknown): { ok: true; name: string } | { ok: false; reason: string } {
  if (typeof raw !== 'string') return { ok: false, reason: 'not-string' }
  const name = raw
  if (name === '') return { ok: false, reason: 'empty' }
  if (name.includes('\0')) return { ok: false, reason: 'nul-byte' }
  if (name.includes('/') || name.includes('\\')) return { ok: false, reason: 'has-path-separator' }
  if (name.startsWith('.')) return { ok: false, reason: 'leading-dot' }
  if (name === '.' || name === '..') return { ok: false, reason: 'dot-or-dotdot' }
  if (/^[A-Za-z]:/.test(name)) return { ok: false, reason: 'windows-drive-letter' }
  // Length cap: 255 is the POSIX NAME_MAX limit on most filesystems.
  if (name.length > 255) return { ok: false, reason: 'too-long' }
  // Verify NodePath.basename agrees — defense against platform-specific
  // path-parser disagreement.
  if (NodePath.basename(name) !== name) return { ok: false, reason: 'basename-mismatch' }
  return { ok: true, name }
}
