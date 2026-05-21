/**
 * Validate an array of upload entries from the webview's `upload` message.
 *
 * SECURITY (DC5 — closes H4, "upload write-anywhere primitive"):
 *   The webview's `upload.handler` builds entries with `name` derived from
 *   pasted/dragged filenames, then sends them to the extension host. The
 *   extension previously wrote each one via
 *     fs.writeFile(NodePath.join(assetsFolder, f.name), content)
 *   `NodePath.join` does NOT reject `..`, absolute paths, or NUL bytes —
 *   so a compromised webview (via the upstream H3 XSS chain) could send
 *   `f.name = "../../../tmp/poc.txt"` and write outside the assets folder.
 *
 *   This helper filters the entries: each entry's `name` is run through
 *   `validateUploadFilename`. Valid entries are kept; invalid entries are
 *   set aside (caller can surface them or drop silently). Non-object
 *   entries and missing fields are also rejected.
 *
 * Extracted from src/extension.ts in C3.1 (DC12) so the
 * message-dispatcher module can import it without a circular dep on
 * extension.ts. Pure: no vscode dependency.
 */

import { validateUploadFilename } from './security/path-validation'

export interface UploadEntry {
  base64: string
  name: string
}

export interface UploadValidationResult {
  valid: UploadEntry[]
  rejected: { reason: string; raw: unknown }[]
}

export function validateUploadEntries(rawFiles: unknown): UploadValidationResult {
  const valid: UploadEntry[] = []
  const rejected: { reason: string; raw: unknown }[] = []

  if (!Array.isArray(rawFiles)) {
    return { valid, rejected: [{ reason: 'files-not-array', raw: rawFiles }] }
  }

  for (const f of rawFiles) {
    if (!f || typeof f !== 'object') {
      rejected.push({ reason: 'entry-not-object', raw: f })
      continue
    }
    const name = (f as any).name
    const base64 = (f as any).base64
    if (typeof base64 !== 'string') {
      rejected.push({ reason: 'base64-not-string', raw: f })
      continue
    }
    const nameCheck = validateUploadFilename(name)
    if (!nameCheck.ok) {
      rejected.push({ reason: `name-${nameCheck.reason}`, raw: f })
      continue
    }
    valid.push({ name: nameCheck.name, base64 })
  }
  return { valid, rejected }
}
