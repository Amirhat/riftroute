// While a change runs, the app sits under ChangeProgress with #root inert,
// where focus() does nothing: a dialog that opens or closes then can't put
// focus where it belongs. focusOrDefer remembers the element that wanted it,
// and ChangeProgress gives it focus once #root is back.

let deferred: HTMLElement | null = null

// focusOrDefer focuses el, or — when that didn't take because el is inert —
// keeps it for takeDeferredFocus. A focus that failed for another reason
// (el is disabled) isn't kept: it's no one's to give back later. A later
// focus that takes clears it.
export function focusOrDefer(el: HTMLElement) {
  el.focus()
  if (document.activeElement === el) deferred = null
  else if (inert(el)) deferred = el
}

// takeDeferredFocus returns (and forgets) the element whose focus didn't
// take, if any. ChangeProgress takes it when #root goes inert (forgetting
// anything from before), and again when it's back.
export function takeDeferredFocus(): HTMLElement | null {
  const el = deferred
  deferred = null
  return el
}

// inert reports whether el is inside an inert element. The property, not
// the attribute: where inert isn't implemented it's set but not reflected.
function inert(el: HTMLElement): boolean {
  for (let n: HTMLElement | null = el; n; n = n.parentElement) {
    if (n.inert) return true
  }
  return false
}
