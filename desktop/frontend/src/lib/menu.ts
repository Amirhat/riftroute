import { VIEWS } from '../components/Sidebar'
import type { View } from '../components/Sidebar'

/** Where a native-menu "nav:*" action (sent by desktop/main.go) takes the app. */
export interface MenuNav {
  view: View
  /** Put the cursor in the Routing Table's "Where does traffic go?" lookup. */
  focusLookup?: boolean
}

/**
 * menuNav maps a menu action to a view, or null for anything that isn't a
 * known destination — an unknown target is ignored instead of switching to a
 * view that doesn't exist (a blank page).
 */
export function menuNav(action: string): MenuNav | null {
  if (!action.startsWith('nav:')) return null
  const target = action.slice(4)
  // Explain is the route lookup at the top of the Routing Table.
  if (target === 'explain') return { view: 'routes', focusLookup: true }
  return (VIEWS as readonly string[]).includes(target) ? { view: target as View } : null
}
