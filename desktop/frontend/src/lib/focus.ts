// While a change runs, the app sits under ChangeProgress with #root inert,
// where focus() does nothing: a dialog that opens or closes then can't put
// focus where it belongs. focusOrDefer remembers the element that wanted it,
// and ChangeProgress gives it focus once #root is back.

let deferred: HTMLElement | null = null

// focusOrDefer focuses el, or — when that didn't take (el is inert) — keeps
// it for takeDeferredFocus. A later focus that takes clears it.
export function focusOrDefer(el: HTMLElement) {
  el.focus()
  deferred = document.activeElement === el ? null : el
}

// takeDeferredFocus returns (and forgets) the element whose focus didn't
// take, if any.
export function takeDeferredFocus(): HTMLElement | null {
  const el = deferred
  deferred = null
  return el
}
