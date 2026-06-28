/** @type {import('tailwindcss').Config} */
// Colors and z-index are SEMANTIC tokens backed by CSS variables (defined in
// index.css for light + dark). Components use only these utilities — never a
// hardcoded hex — so a theme is a pure variable swap (AGENTS §6, spec §8.3).
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base: 'var(--bg)',
        surface: 'var(--surface)',
        elevated: 'var(--surface-2)',
        line: 'var(--border)',
        default: 'var(--text)',
        muted: 'var(--muted)',
        accent: 'var(--accent)',
        'accent-contrast': 'var(--accent-contrast)',
        success: 'var(--success)',
        warning: 'var(--warning)',
        danger: 'var(--danger)',
        vpn: 'var(--vpn)',
        direct: 'var(--direct)',
        'owner-system': 'var(--owner-system)',
        'owner-riftroute': 'var(--owner-riftroute)',
        'owner-vpn': 'var(--owner-vpn)',
      },
      zIndex: {
        base: '0',
        dropdown: '40',
        drawer: '60',
        sheet: '70',
        modal: '90',
        dialog: '100',
        toast: '110',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
