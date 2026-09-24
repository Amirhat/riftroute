/** @type {import('tailwindcss').Config} */
// Colors and z-index are SEMANTIC tokens backed by CSS variables (defined in
// index.css for light + dark). Components use only these utilities — never a
// hardcoded hex — so a theme is a pure variable swap (AGENTS §6, spec §8.3).

// A color token reads its theme's RGB channels, so opacity modifiers work
// (bg-danger/10, border-line/60); a plain var() color can't take an alpha.
const token = (name) => `rgb(var(--${name}-rgb) / <alpha-value>)`

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base: token('bg'),
        surface: token('surface'),
        elevated: token('surface-2'),
        line: token('border'),
        default: token('text'),
        muted: token('muted'),
        accent: token('accent'),
        'accent-contrast': token('accent-contrast'),
        success: token('success'),
        warning: token('warning'),
        danger: token('danger'),
        vpn: token('vpn'),
        direct: token('direct'),
        'owner-system': token('owner-system'),
        'owner-riftroute': token('owner-riftroute'),
        'owner-vpn': token('owner-vpn'),
        knob: token('knob'),
        'toggle-off': token('toggle-off'),
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
  plugins: [
    // `mac:` applies only inside the macOS window, where the traffic lights
    // overlay the content (lib/platform.ts tags <html data-platform>).
    function ({ addVariant }) {
      addVariant('mac', '[data-platform="darwin"] &')
    },
  ],
}
