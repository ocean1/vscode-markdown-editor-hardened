/**
 * Tiny synthetic-keyboard-events helper. Replaces the single use of
 * `@testing-library/user-event/dist/keyboard` from fix-table-ir.ts so
 * we can drop the testing-library deps (~300KB of bundled JS that was
 * only used for vditor table hotkey dispatch).
 *
 * Input syntax (subset of @testing-library/user-event's keyboard DSL):
 *   - `{ctrl}...{/ctrl}` hold Ctrl during the inner sequence
 *   - `{shift}...{/shift}` hold Shift during the inner sequence
 *   - `{meta}...{/meta}` hold Meta (Cmd on macOS) during the inner sequence
 *   - `{alt}...{/alt}` hold Alt during the inner sequence
 *   - any other single character: press + release that key
 *
 * Modifier opens/closes can NEST. The sequence "{ctrl}{shift}l{/shift}{/ctrl}"
 * presses Ctrl down, Shift down, dispatches a keydown+keyup for "l" with
 * both ctrlKey:true + shiftKey:true, then Shift up, Ctrl up.
 *
 * Dispatch target: the element passed via the `target` option (defaults
 * to document.body). Events bubble — vditor's IR element's keydown
 * listener picks them up.
 *
 * @example
 *   sendKeySequence('{ctrl}{shift}l{/shift}{/ctrl}', { target: ir })
 */

interface ModState {
  ctrl: boolean;
  shift: boolean;
  meta: boolean;
  alt: boolean;
}

type ModName = keyof ModState;

const MOD_OPEN: Record<string, ModName> = {
  '{ctrl}': 'ctrl',
  '{shift}': 'shift',
  '{meta}': 'meta',
  '{alt}': 'alt',
};

const MOD_CLOSE: Record<string, ModName> = {
  '{/ctrl}': 'ctrl',
  '{/shift}': 'shift',
  '{/meta}': 'meta',
  '{/alt}': 'alt',
};

interface SendKeyOptions {
  target?: Element | Document;
}

function keyForChar(ch: string): { key: string; code: string } {
  // Map common single-character keys to the proper KeyboardEvent.key + code.
  // Letters: key is the lowercase letter, code is `Key<UC>`.
  if (/^[a-z]$/.test(ch)) return { key: ch, code: `Key${ch.toUpperCase()}` };
  if (/^[A-Z]$/.test(ch)) return { key: ch.toLowerCase(), code: `Key${ch}` };
  if (/^[0-9]$/.test(ch)) return { key: ch, code: `Digit${ch}` };
  // The handful of punctuation keys vditor's table hotkeys actually use:
  switch (ch) {
    case '=': return { key: '=', code: 'Equal' };
    case '+': return { key: '+', code: 'Equal' }; // shifted '='
    case '-': return { key: '-', code: 'Minus' };
    case '_': return { key: '_', code: 'Minus' }; // shifted '-'
  }
  // Fallback: use the character verbatim as both key and code.
  return { key: ch, code: ch };
}

function fireKey(target: Element | Document, type: 'keydown' | 'keyup', ch: string, mods: ModState) {
  const { key, code } = keyForChar(ch);
  const ev = new KeyboardEvent(type, {
    key,
    code,
    ctrlKey: mods.ctrl,
    shiftKey: mods.shift,
    metaKey: mods.meta,
    altKey: mods.alt,
    bubbles: true,
    cancelable: true,
  });
  target.dispatchEvent(ev);
}

function fireMod(target: Element | Document, type: 'keydown' | 'keyup', mod: ModName) {
  const map: Record<ModName, { key: string; code: string }> = {
    ctrl: { key: 'Control', code: 'ControlLeft' },
    shift: { key: 'Shift', code: 'ShiftLeft' },
    meta: { key: 'Meta', code: 'MetaLeft' },
    alt: { key: 'Alt', code: 'AltLeft' },
  };
  const m = map[mod];
  // Build the modifier state as it is JUST BEFORE this fires.
  // For keydown on a modifier: the modifier becomes active AFTER this event,
  // so we pass mods as the pre-state. For keyup: mods is the post-state.
  // We pass the current snapshot — callers update state outside this helper.
  const ev = new KeyboardEvent(type, {
    key: m.key,
    code: m.code,
    bubbles: true,
    cancelable: true,
  });
  target.dispatchEvent(ev);
}

export function sendKeySequence(seq: string, opts: SendKeyOptions = {}): void {
  const target = opts.target ?? document.body;
  const mods: ModState = { ctrl: false, shift: false, meta: false, alt: false };

  let i = 0;
  while (i < seq.length) {
    // Try to match a {mod}/{/mod} token starting here.
    if (seq[i] === '{') {
      const closeIdx = seq.indexOf('}', i);
      if (closeIdx !== -1) {
        const token = seq.slice(i, closeIdx + 1);
        if (token in MOD_OPEN) {
          const m = MOD_OPEN[token];
          mods[m] = true;
          fireMod(target, 'keydown', m);
          i = closeIdx + 1;
          continue;
        }
        if (token in MOD_CLOSE) {
          const m = MOD_CLOSE[token];
          mods[m] = false;
          fireMod(target, 'keyup', m);
          i = closeIdx + 1;
          continue;
        }
        // Unknown {...} token: fall through and treat the '{' as a literal.
      }
    }
    // Single-character key — fire keydown + keyup with current modifier state.
    const ch = seq[i];
    fireKey(target, 'keydown', ch, mods);
    fireKey(target, 'keyup', ch, mods);
    i++;
  }
}
