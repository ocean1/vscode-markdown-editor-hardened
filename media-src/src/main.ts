import './preload'

import {
  fileToBase64,
  fixCut,
  fixDarkTheme,
  fixLinkClick,
  fixPanelHover,
  handleToolbarClick,
  saveVditorOptions,
} from './utils'

import { merge } from 'lodash'
import Vditor from 'vditor'
import { format } from 'date-fns'
import 'vditor/dist/index.css'
import { t, lang } from './lang'
import { toolbar } from './toolbar'
import { fixTableIr } from './fix-table-ir'
import './main.css'

function initVditor(msg) {
  console.log('msg', msg)
  let inputTimer
  let defaultOptions: any = {}
  defaultOptions = merge(defaultOptions, msg.options, {
    preview: {
      math: {
        inlineDigit: true,
      }
    }
  })
  // DC7 / C1.14: read the locally-bundled vditor assets URL set by the
  // host in the inline init script (`window.__vditorCdn`). Falls back to
  // the empty string if unset — vditor would then default to jsdelivr,
  // which is what we explicitly do NOT want. CSP also blocks jsdelivr
  // post-C1.14, so a fallback to jsdelivr would just produce a load
  // error, not a security regression. Logging the empty-string case so
  // it surfaces during development.
  const cdn = (window as any).__vditorCdn || ''
  if (!cdn) {
    console.warn('[markdown-editor-hardened] window.__vditorCdn unset; vditor will fail to load assets')
  }
  // vditor 3.11's content-theme (the rendered-markdown styling — headings,
  // code blocks, tables, blockquotes) is loaded dynamically from
  // `${preview.theme.path}/<current>.css`. Upstream set
  // `preview.theme.current` without `path`, so vditor's loader fell back
  // to its hardcoded default CDN path. With our local-bundle, that default
  // doesn't resolve — the content-theme never loads, and the editor
  // renders with vditor's fallback styles. Set `path` explicitly so it
  // points at the local css/content-theme directory.
  const contentThemePath = cdn ? `${cdn}/dist/css/content-theme` : ''

  // Apply theme from VS Code AFTER merge so it takes precedence over stored options
  //
  // hljs.style picks the syntax-highlighting palette for fenced code blocks.
  // Default upstream is "github" (light) which clashes with dark VS Code
  // themes. We pin to vs2015 (dark) / vs (light) — the closest matches to
  // VS Code's actual syntax token colors.
  if (msg.theme === 'dark') {
    defaultOptions.theme = 'dark'
    defaultOptions.preview = defaultOptions.preview || {}
    defaultOptions.preview.theme = { current: 'dark', path: contentThemePath }
    defaultOptions.preview.hljs = defaultOptions.preview.hljs || {}
    defaultOptions.preview.hljs.style = 'vs2015'
  } else if (msg.theme === 'light') {
    defaultOptions.theme = 'classic'
    defaultOptions.preview = defaultOptions.preview || {}
    defaultOptions.preview.theme = { current: 'light', path: contentThemePath }
    defaultOptions.preview.hljs = defaultOptions.preview.hljs || {}
    defaultOptions.preview.hljs.style = 'vs'
  }
  if (window.vditor) {
    vditor.destroy()
    window.vditor = null
  }
  window.vditor = new Vditor('app', {
    width: '100%',
    height: '100%',
    minHeight: '100%',
    lang,
    cdn,
    value: msg.content,
    mode: 'ir',
    cache: { enable: false },
    toolbar,
    toolbarConfig: { pin: true },
    ...defaultOptions,
    after() {
      fixDarkTheme()
      handleToolbarClick()
      fixTableIr()
      fixPanelHover()
      // Auto-focus on initial open (per upstream PR #154 — credit LeonardoRick).
      vditor.focus()
    },
    input() {
      inputTimer && clearTimeout(inputTimer)
      inputTimer = setTimeout(() => {
        vscode.postMessage({ command: 'edit', content: vditor.getValue() })
      }, 100)
    },
    upload: {
      url: '/fuzzy', // 没有 url 参数粘贴图片无法上传 see: https://github.com/Vanessa219/vditor/blob/d7628a0a7cfe5d28b055469bf06fb0ba5cfaa1b2/src/ts/util/fixBrowserBehavior.ts#L1409
      async handler(files) {
        // console.log('files', files)
        let fileInfos = await Promise.all(
          files.map(async (f) => {
            const d = new Date()
            return {
              base64: await fileToBase64(f),
              name: `${format(new Date(), 'yyyyMMdd_HHmmss')}_${f.name}`.replace(
                /[^\w-_.]+/g,
                '_'
              ),
            }
          })
        )
        vscode.postMessage({
          command: 'upload',
          files: fileInfos,
        })
        // vditor 3.11+ upload.handler must return null on success (was
        // implicit-undefined in 3.8.x). See PR #142 for the API change.
        return null
      },
    },
  })
}

window.addEventListener('message', (e) => {
  const msg = e.data
  // console.log('msg from vscode', msg)
  switch (msg.command) {
    case 'update': {
      if (msg.type === 'init') {
        if (msg.options && msg.options.useVscodeThemeColor) {
          document.body.setAttribute('data-use-vscode-theme-color', '1')
        } else {
          document.body.setAttribute('data-use-vscode-theme-color', '0')
        }
        try {
          initVditor(msg)
        } catch (error) {
          // reset options when error
          console.error(error)
          initVditor({ content: msg.content })
          saveVditorOptions()
        }
        console.log('initVditor')
      } else {
        vditor.setValue(msg.content)
        console.log('setValue')
      }
      break
    }
    case 'focus': {
      // Re-reveal focus (per upstream PR #154 — credit LeonardoRick).
      vditor.focus()
      break
    }
    case 'uploaded': {
      msg.files.forEach((f) => {
        if (f.endsWith('.wav')) {
          vditor.insertValue(
            `\n\n<audio controls="controls" src="${f}"></audio>\n\n`
          )
        } else {
          const i = new Image()
          i.src = f
          i.onload = () => {
            vditor.insertValue(`\n\n![](${f})\n\n`)
          }
          i.onerror = () => {
            vditor.insertValue(`\n\n[${f.split('/').slice(-1)[0]}](${f})\n\n`)
          }
        }
      })
      break
    }
    default:
      break
  }
})

fixLinkClick()
fixCut()

vscode.postMessage({ command: 'ready' })
