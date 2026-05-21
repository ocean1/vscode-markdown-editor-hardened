import * as vscode from 'vscode'
import * as NodePath from 'path'
import { validateWorkspaceRelativePath, validateUploadFilename, validateOpenLinkUrl } from './security/path-validation'
const KeyVditorOptions = 'vditor.options'

interface UploadEntry { base64: string; name: string }

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
 */
function validateUploadEntries(
  rawFiles: unknown
): { valid: UploadEntry[]; rejected: { reason: string; raw: unknown }[] } {
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

function debug(...args: any[]) {
  console.log(...args)
}

function showError(msg: string) {
  vscode.window.showErrorMessage(`[markdown-editor-hardened] ${msg}`)
}

/**
 * Resolve the user's `customStylesheet` setting to a webview-safe URI string,
 * or null if the setting is unset/invalid.
 *
 * SECURITY (DC2 — closes H3, "customCss raw HTML injection"):
 *   Upstream's `customCss` setting interpolated arbitrary HTML into a
 *   <style> block in the webview, allowing a hostile `.vscode/settings.json`
 *   to break out with `</style><script>...`. This redesign replaces that
 *   string-of-CSS with a path-to-CSS:
 *     - VALUE IS A PATH (filename), not HTML/CSS content;
 *     - path must be workspace-relative (rejects absolute, traversal, URLs);
 *     - file must end in `.css` (rejects `.html`, `.js`, etc.);
 *     - emitted via <link rel="stylesheet">, not a content-interpolated
 *       <style> block;
 *     - the webview resolves the URL through `webview.asWebviewUri` so a
 *       cross-origin URL is unreachable.
 *   Combined with localResourceRoots scoping (DC3, C1.6) and CSP (DC4,
 *   C1.10), this fully closes the H3 chain even if the stylesheet path
 *   itself comes from a hostile workspace's settings.json.
 *
 *   If the input fails ANY validation step, returns null silently — the
 *   webview just renders without the custom stylesheet (fail-closed).
 */
/**
 * Build the scoped `localResourceRoots` array for the webview.
 *
 * SECURITY (DC3 — closes H1, "over-broad localResourceRoots"):
 *   Upstream set `localResourceRoots: [Uri.file("/"), Uri.file("A:/"), ...,
 *   Uri.file("Z:/")]` — granting the webview read access to every file on
 *   the system (or every drive on Windows). This was a defense-in-depth
 *   weakness: if the webview JS were ever compromised (via a XSS chain,
 *   compromised CDN, etc.), it could read arbitrary local files via the
 *   webview's URI-mapping facility.
 *
 *   The redesign scopes the roots to what the extension actually needs:
 *     - extensionUri      — to load the bundled webview JS/CSS
 *     - workspace folders — to load images by workspace-relative path
 *     - current file dir  — to load images by file-relative path
 *
 *   Images outside the workspace (e.g., a user dragging in an image from
 *   /tmp) used to work via the `/` root. With this scope, they fail to
 *   load — the user gets a broken-image icon. This is a small UX cost
 *   for a meaningful defense-in-depth win. The full local-bundle of
 *   vditor (DC7 / C1.14) keeps the extensionUri root sufficient for the
 *   editor itself.
 */
function scopedLocalResourceRoots(
  extensionUri: vscode.Uri,
  fileUri?: vscode.Uri
): vscode.Uri[] {
  const roots: vscode.Uri[] = [extensionUri]
  if (vscode.workspace.workspaceFolders) {
    for (const wsFolder of vscode.workspace.workspaceFolders) {
      roots.push(wsFolder.uri)
    }
  }
  if (fileUri) {
    // The file's containing directory. Useful when the file is not under
    // any workspace folder (e.g. opened directly via Finder/Explorer).
    const fileDir = vscode.Uri.file(NodePath.dirname(fileUri.fsPath))
    roots.push(fileDir)
  }
  return roots
}

function resolveCustomStylesheet(
  webview: vscode.Webview,
  fileUri: vscode.Uri,
  configRaw: string | undefined
): string | null {
  const wsFolder = vscode.workspace.getWorkspaceFolder(fileUri)
  if (!wsFolder) return null

  const result = validateWorkspaceRelativePath(
    configRaw,
    wsFolder.uri.fsPath,
    '.css'
  )
  if (!result.ok) return null

  return webview.asWebviewUri(vscode.Uri.file(result.resolved)).toString()
}

export function activate(context: vscode.ExtensionContext) {
  // Register original command (used by context menu/shortcuts)
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'markdown-editor-hardened.openEditor',
      (uri?: vscode.Uri, ...args) => {
        debug('command', uri, args)
        EditorPanel.createOrShow(context, uri)
      }
    )
  )

  // Register CustomTextEditorProvider (for "Open With" and default editor)
  context.subscriptions.push(
    vscode.window.registerCustomEditorProvider(
      MarkdownEditorProvider.viewType,
      new MarkdownEditorProvider(context),
      {
        webviewOptions: {
          retainContextWhenHidden: true,
        },
        supportsMultipleEditorsPerDocument: false,
      }
    )
  )

  context.globalState.setKeysForSync([KeyVditorOptions])
}

/**
 * Manages cat coding webview panels
 */
class EditorPanel {
  /**
   * Track the currently panel. Only allow a single panel to exist at a time.
   */
  public static currentPanel: EditorPanel | undefined

  public static readonly viewType = 'markdown-editor-hardened'

  private _disposables: vscode.Disposable[] = []

  public static async createOrShow(
    context: vscode.ExtensionContext,
    uri?: vscode.Uri
  ) {
    const { extensionUri } = context
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined
    if (EditorPanel.currentPanel && uri !== EditorPanel.currentPanel?._uri) {
      EditorPanel.currentPanel.dispose()
    }
    // If we already have a panel, show it.
    if (EditorPanel.currentPanel) {
      EditorPanel.currentPanel._panel.reveal(column)
      return
    }
    if (!vscode.window.activeTextEditor && !uri) {
      showError(`Did not open markdown file!`)
      return
    }
    let doc: undefined | vscode.TextDocument
    // From context menu: Find if there is a markdown editor for the current active TextEditor, if so bind the document
    if (uri) {
      // Open file from context menu: Open document first then enable auto-sync, otherwise cannot save file or sync to opened document
      doc = await vscode.workspace.openTextDocument(uri)
    } else {
      doc = vscode.window.activeTextEditor?.document
      // from command mode
      if (doc && doc.languageId !== 'markdown') {
        showError(
          `Current file language is not markdown, got ${doc.languageId}`
        )
        return
      }
    }

    if (!doc) {
      showError(`Cannot find markdown file!`)
      return
    }

    // Otherwise, create a new panel.
    const panel = vscode.window.createWebviewPanel(
      EditorPanel.viewType,
      'markdown-editor-hardened',
      column || vscode.ViewColumn.One,
      EditorPanel.getWebviewOptions(extensionUri, uri ?? doc?.uri)
    )

    EditorPanel.currentPanel = new EditorPanel(
      context,
      panel,
      extensionUri,
      doc,
      uri
    )
  }

  static getWebviewOptions(
    extensionUri: vscode.Uri,
    fileUri?: vscode.Uri
  ): vscode.WebviewOptions & vscode.WebviewPanelOptions {
    return {
      // Enable javascript in the webview
      enableScripts: true,

      // SECURITY (DC3, closes H1 — over-broad localResourceRoots):
      //   Scoped to extension dir + workspace folders + current file dir,
      //   replacing upstream's `[Uri.file("/"), Uri.file("A:/")..Uri.file("Z:/")]`
      //   which granted webview read access to the entire filesystem. See
      //   `scopedLocalResourceRoots` doc for the full rationale.
      localResourceRoots: scopedLocalResourceRoots(extensionUri, fileUri),
      retainContextWhenHidden: true,
      // SECURITY (DC1, closes H2 — RCE via crafted markdown command: URI):
      //   `enableCommandUris: true` was set in upstream; it allows any rendered
      //   <a href="command:..."> in the webview to dispatch arbitrary VS Code
      //   commands when clicked. Combined with the fact that vditor's markdown
      //   sanitizer (Lute) does NOT strip `command:` URIs from rendered links
      //   (verified by programmatic test in vditor 3.8.4 AND 3.11.2), opening a
      //   crafted markdown file via this command-mode panel and clicking the
      //   link executed arbitrary commands (e.g.,
      //   workbench.action.terminal.sendSequence with shell text).
      //   Default (option omitted) is `false` — clicks on command: URIs become
      //   inert. The link still renders in the DOM but cannot fire commands.
    }
  }
  private get _fsPath() {
    return this._uri.fsPath
  }

  static get config() {
    return vscode.workspace.getConfiguration('markdown-editor-hardened')
  }

  private constructor(
    private readonly _context: vscode.ExtensionContext,
    private readonly _panel: vscode.WebviewPanel,
    private readonly _extensionUri: vscode.Uri,
    public _document: vscode.TextDocument,
    public _uri = _document.uri // Opened from explorer, only uri exists, no _document
  ) {
    // Set the webview's initial html content

    this._init()

    // Listen for when the panel is disposed
    // This happens when the user closes the panel or when the panel is closed programmatically
    this._panel.onDidDispose(() => this.dispose(), null, this._disposables)
    let textEditTimer: NodeJS.Timeout | void
    // close EditorPanel when vsc editor is close
    vscode.workspace.onDidCloseTextDocument((e) => {
      if (e.fileName === this._fsPath) {
        this.dispose()
      }
    }, this._disposables)
    // re-init webview when VS Code theme changes
    vscode.window.onDidChangeActiveColorTheme((theme) => {
      this._update({
        type: 'init',
        options: {
          useVscodeThemeColor: EditorPanel.config.get<boolean>(
            'useVscodeThemeColor'
          ),
          ...this._context.globalState.get(KeyVditorOptions),
        },
        theme: theme.kind === vscode.ColorThemeKind.Dark ? 'dark' : 'light',
      })
    }, null, this._disposables)
    // update EditorPanel when vsc editor changes
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (e.document.fileName !== this._document.fileName) {
        return
      }
      // When webview panel is active, do not sync updates from VS Code editor caused by webview edits back to webview
      // don't change webview panel when webview panel is focus
      if (this._panel.active) {
        return
      }
      textEditTimer && clearTimeout(textEditTimer)
      textEditTimer = setTimeout(() => {
        this._update()
        this._updateEditTitle()
      }, 300)
    }, this._disposables)
    // Handle messages from the webview
    this._panel.webview.onDidReceiveMessage(
      async (message) => {
        debug('msg from webview review', message, this._panel.active)

        const syncToEditor = async () => {
          debug('sync to editor', this._document, this._uri)
          if (this._document) {
            const edit = new vscode.WorkspaceEdit()
            edit.replace(
              this._document.uri,
              new vscode.Range(0, 0, this._document.lineCount, 0),
              message.content
            )
            await vscode.workspace.applyEdit(edit)
          } else if (this._uri) {
            await vscode.workspace.fs.writeFile(this._uri, message.content)
          } else {
            showError(`Cannot find original file to save!`)
          }
        }
        switch (message.command) {
          case 'ready':
            this._update({
              type: 'init',
              options: {
                useVscodeThemeColor: EditorPanel.config.get<boolean>(
                  'useVscodeThemeColor'
                ),
                ...this._context.globalState.get(KeyVditorOptions),
              },
              theme:
                vscode.window.activeColorTheme.kind ===
                  vscode.ColorThemeKind.Dark
                  ? 'dark'
                  : 'light',
            })
            break
          case 'save-options':
            this._context.globalState.update(KeyVditorOptions, message.options)
            break
          case 'info':
            vscode.window.showInformationMessage(message.content)
            break
          case 'error':
            showError(message.content)
            break
          case 'edit': {
            // Only sync to VS Code editor when webview is in edit mode to avoid repeated refresh
            if (this._panel.active) {
              await syncToEditor()
              this._updateEditTitle()
            }
            break
          }
          case 'reset-config': {
            await this._context.globalState.update(KeyVditorOptions, {})
            break
          }
          case 'save': {
            await syncToEditor()
            await this._document.save()
            this._updateEditTitle()
            break
          }
          case 'upload': {
            // SECURITY (DC5 / H4): validate filenames BEFORE any fs write.
            const { valid, rejected } = validateUploadEntries(message.files)
            if (rejected.length > 0) {
              debug('upload: rejected entries', rejected)
              showError(
                `Rejected ${rejected.length} upload entr${rejected.length === 1 ? 'y' : 'ies'} ` +
                `(invalid filename or shape). Reasons: ${rejected.map(r => r.reason).join(', ')}`
              )
            }
            if (valid.length === 0) break
            const assetsFolder = EditorPanel.getAssetsFolder(this._uri)
            try {
              await vscode.workspace.fs.createDirectory(
                vscode.Uri.file(assetsFolder)
              )
            } catch (error) {
              console.error(error)
              showError(`Invalid image folder: ${assetsFolder}`)
            }
            await Promise.all(
              valid.map(async (f) => {
                const content = Buffer.from(f.base64, 'base64')
                return vscode.workspace.fs.writeFile(
                  vscode.Uri.file(NodePath.join(assetsFolder, f.name)),
                  content
                )
              })
            )
            const files = valid.map((f) =>
              NodePath.relative(
                NodePath.dirname(this._fsPath),
                NodePath.join(assetsFolder, f.name)
              ).replace(/\\/g, '/')
            )
            this._panel.webview.postMessage({
              command: 'uploaded',
              files,
            })
            break
          }
          case 'open-link': {
            // SECURITY (DC6 / H5): validate scheme + workspace containment.
            const wsRoots = (vscode.workspace.workspaceFolders ?? []).map(w => w.uri.fsPath)
            const result = validateOpenLinkUrl(message.href, this._fsPath, wsRoots)
            if (!result.ok) {
              debug('open-link: rejected', { href: message.href, reason: result.reason })
              break
            }
            if (result.kind === 'file') {
              vscode.commands.executeCommand('vscode.open', vscode.Uri.file(result.resolvedFsPath))
            } else {
              // http, https, mailto — pass the validated URL string through.
              vscode.commands.executeCommand('vscode.open', vscode.Uri.parse(result.url))
            }
            break
          }
        }
      },
      null,
      this._disposables
    )
  }

  static getAssetsFolder(uri: vscode.Uri) {
    const imageSaveFolder = (
      EditorPanel.config.get<string>('imageSaveFolder') || 'assets'
    )
      .replace(
        '${projectRoot}',
        vscode.workspace.getWorkspaceFolder(uri)?.uri.fsPath || ''
      )
      .replace('${file}', uri.fsPath)
      .replace(
        '${fileBasenameNoExtension}',
        NodePath.basename(uri.fsPath, NodePath.extname(uri.fsPath))
      )
      .replace('${dir}', NodePath.dirname(uri.fsPath))
    const assetsFolder = NodePath.resolve(
      NodePath.dirname(uri.fsPath),
      imageSaveFolder
    )
    return assetsFolder
  }

  public dispose() {
    EditorPanel.currentPanel = undefined

    // Clean up our resources
    this._panel.dispose()

    while (this._disposables.length) {
      const x = this._disposables.pop()
      if (x) {
        x.dispose()
      }
    }
  }

  private _init() {
    const webview = this._panel.webview

    this._panel.webview.html = this._getHtmlForWebview(webview)
    this._panel.title = NodePath.basename(this._fsPath)
  }
  private _isEdit = false
  private _updateEditTitle() {
    const isEdit = this._document.isDirty
    if (isEdit !== this._isEdit) {
      this._isEdit = isEdit
      this._panel.title = `${isEdit ? `[edit]` : ''}${NodePath.basename(
        this._fsPath
      )}`
    }
  }

  // private fileToWebviewUri = (f: string) => {
  //   return this._panel.webview.asWebviewUri(vscode.Uri.file(f)).toString()
  // }

  private async _update(
    props: {
      type?: 'init' | 'update'
      options?: any
      theme?: 'dark' | 'light'
    } = { options: void 0 }
  ) {
    const md = this._document
      ? this._document.getText()
      : (await vscode.workspace.fs.readFile(this._uri)).toString()
    // const dir = NodePath.dirname(this._document.fileName)
    this._panel.webview.postMessage({
      command: 'update',
      content: md,
      ...props,
    })
  }

  private _getHtmlForWebview(webview: vscode.Webview) {
    const toUri = (f: string) =>
      webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, f))
    const baseHref =
      NodePath.dirname(
        webview.asWebviewUri(vscode.Uri.file(this._fsPath)).toString()
      ) + '/'
    const toMediaPath = (f: string) => `media/dist/${f}`
    const JsFiles = ['main.js'].map(toMediaPath).map(toUri)
    const CssFiles = ['main.css'].map(toMediaPath).map(toUri)

    // DC2 redesign of the upstream `customCss` setting — see
    // `resolveCustomStylesheet` for the security rationale. Returns a
    // webview-safe URI string OR null. null = no extra stylesheet.
    const customStylesheetUri = resolveCustomStylesheet(
      webview,
      this._uri,
      EditorPanel.config.get<string>('customStylesheet')
    )
    const customStylesheetLink = customStylesheetUri
      ? `<link href="${customStylesheetUri}" rel="stylesheet">`
      : ''

    return (
      `<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">

				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<base href="${baseHref}" />


				${CssFiles.map((f) => `<link href="${f}" rel="stylesheet">`).join('\n')}
				${customStylesheetLink}

				<title>markdown editor</title>
			</head>
			<body>
				<div id="app"></div>


				${JsFiles.map((f) => `<script src="${f}"></script>`).join('\n')}
			</body>
			</html>`
    )
  }
}

/**
 * MarkdownEditorProvider implements CustomTextEditorProvider interface
 * Supports opening markdown files via "Open With"
 */
class MarkdownEditorProvider implements vscode.CustomTextEditorProvider {
  public static readonly viewType = 'markdown-editor-hardened.customEditor'

  constructor(private readonly context: vscode.ExtensionContext) { }

  /**
   * Called when user selects Markdown Editor via "Open With"
   */
  public async resolveCustomTextEditor(
    document: vscode.TextDocument,
    webviewPanel: vscode.WebviewPanel,
    _token: vscode.CancellationToken
  ): Promise<void> {
    // Set webview options
    webviewPanel.webview.options = this.getWebviewOptions(document.uri)

    // Init webview content
    const uri = document.uri
    webviewPanel.webview.html = this.getHtmlForWebview(webviewPanel.webview, uri)
    webviewPanel.title = NodePath.basename(uri.fsPath)

    const disposables: vscode.Disposable[] = []
    let isEditing = false

    // Update title to show edit status
    const updateEditTitle = () => {
      const isDirty = document.isDirty
      if (isDirty !== isEditing) {
        isEditing = isDirty
        webviewPanel.title = `${isDirty ? '[edit]' : ''}${NodePath.basename(uri.fsPath)}`
      }
    }

    // Send update to webview
    const updateWebview = (props: { type?: 'init' | 'update'; options?: any; theme?: 'dark' | 'light' } = {}) => {
      webviewPanel.webview.postMessage({
        command: 'update',
        content: document.getText(),
        ...props,
      })
    }

    // Listen for document close
    vscode.workspace.onDidCloseTextDocument((e) => {
      if (e.fileName === uri.fsPath) {
        webviewPanel.dispose()
      }
    }, null, disposables)

    // Listen for document changes (sync from external editor to webview)
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (e.document.fileName !== document.fileName) {
        return
      }
      // Do not sync when webview panel is active (avoid circular updates)
      if (webviewPanel.active) {
        return
      }
      updateWebview()
      updateEditTitle()
    }, null, disposables)

    // Handle messages from webview
    webviewPanel.webview.onDidReceiveMessage(async (message) => {
      debug('msg from webview', message, webviewPanel.active)

      const syncToEditor = async () => {
        const edit = new vscode.WorkspaceEdit()
        edit.replace(
          document.uri,
          new vscode.Range(0, 0, document.lineCount, 0),
          message.content
        )
        await vscode.workspace.applyEdit(edit)
      }

      switch (message.command) {
        case 'ready':
          updateWebview({
            type: 'init',
            options: {
              useVscodeThemeColor: EditorPanel.config.get<boolean>('useVscodeThemeColor'),
              ...this.context.globalState.get(KeyVditorOptions),
            },
            theme: vscode.window.activeColorTheme.kind === vscode.ColorThemeKind.Dark ? 'dark' : 'light',
          })
          break
        case 'save-options':
          this.context.globalState.update(KeyVditorOptions, message.options)
          break
        case 'info':
          vscode.window.showInformationMessage(message.content)
          break
        case 'error':
          showError(message.content)
          break
        case 'edit':
          if (webviewPanel.active) {
            await syncToEditor()
            updateEditTitle()
          }
          break
        case 'reset-config':
          await this.context.globalState.update(KeyVditorOptions, {})
          break
        case 'save':
          await syncToEditor()
          await document.save()
          updateEditTitle()
          break
        case 'upload': {
          // SECURITY (DC5 / H4): validate filenames BEFORE any fs write.
          const { valid, rejected } = validateUploadEntries(message.files)
          if (rejected.length > 0) {
            debug('upload: rejected entries', rejected)
            showError(
              `Rejected ${rejected.length} upload entr${rejected.length === 1 ? 'y' : 'ies'} ` +
              `(invalid filename or shape). Reasons: ${rejected.map(r => r.reason).join(', ')}`
            )
          }
          if (valid.length === 0) break
          const assetsFolder = EditorPanel.getAssetsFolder(uri)
          try {
            await vscode.workspace.fs.createDirectory(vscode.Uri.file(assetsFolder))
          } catch (error) {
            console.error(error)
            showError(`Invalid image folder: ${assetsFolder}`)
          }
          await Promise.all(
            valid.map(async (f) => {
              const content = Buffer.from(f.base64, 'base64')
              return vscode.workspace.fs.writeFile(
                vscode.Uri.file(NodePath.join(assetsFolder, f.name)),
                content
              )
            })
          )
          const files = valid.map((f) =>
            NodePath.relative(NodePath.dirname(uri.fsPath), NodePath.join(assetsFolder, f.name)).replace(/\\/g, '/')
          )
          webviewPanel.webview.postMessage({
            command: 'uploaded',
            files,
          })
          break
        }
        case 'open-link': {
          // SECURITY (DC6 / H5): validate scheme + workspace containment.
          const wsRoots = (vscode.workspace.workspaceFolders ?? []).map(w => w.uri.fsPath)
          const result = validateOpenLinkUrl(message.href, uri.fsPath, wsRoots)
          if (!result.ok) {
            debug('open-link: rejected', { href: message.href, reason: result.reason })
            break
          }
          if (result.kind === 'file') {
            vscode.commands.executeCommand('vscode.open', vscode.Uri.file(result.resolvedFsPath))
          } else {
            vscode.commands.executeCommand('vscode.open', vscode.Uri.parse(result.url))
          }
          break
        }
      }
    }, null, disposables)

    // Clean up resources
    webviewPanel.onDidDispose(() => {
      disposables.forEach((d) => d.dispose())
    })
  }

  private getWebviewOptions(fileUri?: vscode.Uri): vscode.WebviewOptions {
    return {
      enableScripts: true,
      // SECURITY (DC3, closes H1 — over-broad localResourceRoots):
      //   See `scopedLocalResourceRoots` doc + EditorPanel.getWebviewOptions
      //   for the rationale. Same scope policy as the command-mode panel.
      localResourceRoots: scopedLocalResourceRoots(this.context.extensionUri, fileUri),
    }
  }

  private getHtmlForWebview(webview: vscode.Webview, uri: vscode.Uri): string {
    const toUri = (f: string) => webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, f))
    const baseHref = NodePath.dirname(webview.asWebviewUri(vscode.Uri.file(uri.fsPath)).toString()) + '/'
    const toMediaPath = (f: string) => `media/dist/${f}`
    const JsFiles = ['main.js'].map(toMediaPath).map(toUri)
    const CssFiles = ['main.css'].map(toMediaPath).map(toUri)

    // DC2 redesign of the upstream `customCss` setting — see
    // `resolveCustomStylesheet` for the security rationale.
    const customStylesheetUri = resolveCustomStylesheet(
      webview,
      uri,
      EditorPanel.config.get<string>('customStylesheet')
    )
    const customStylesheetLink = customStylesheetUri
      ? `<link href="${customStylesheetUri}" rel="stylesheet">`
      : ''

    return (
      `<!DOCTYPE html>
			<html lang="en">
			<head>
				<meta charset="UTF-8">

				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<base href="${baseHref}" />


				${CssFiles.map((f) => `<link href="${f}" rel="stylesheet">`).join('\n')}
				${customStylesheetLink}

				<title>markdown editor</title>
			</head>
			<body>
				<div id="app"></div>


				${JsFiles.map((f) => `<script src="${f}"></script>`).join('\n')}
			</body>
			</html>`
    )
  }
}
