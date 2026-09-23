# riftroute.tellnew.tech — design record

The public site (landing `/` and `/fa`, sign-in, admin) is a **line diagram of
your own traffic**: one trunk leaves your computer and forks; every stop is a
rule with its reason. Everything below is what the built pages use — change
the system here and in `static/site.css` together.

## Constraints that shape everything

- **No JavaScript.** The CSP has no `script-src`; motion and states are CSS only.
- **No third-party requests.** Fonts and images are served from `/static/<hash>/`.
- **Two directions.** English is left-to-right, Persian right-to-left. Use
  logical properties only (`inset-inline-*`, `margin-block-*`, …). Anything
  drawn with a direction (the fork SVGs, dashed segments, directional glyphs)
  is mirrored under `[dir="rtl"]`. Addresses, interfaces and domains are always
  left-to-right (`<code dir="ltr">`, or `\u2066…\u2069` isolates inside copy).
- **Light and dark** swap tokens under `prefers-color-scheme`; components read
  tokens only, never hex values.

## Colour roles

| Token | Light | Dark | Meaning |
|---|---|---|---|
| `--ground` | `#ffffff` | `#0f1012` | The one map ground for every section (dark is neutral graphite, not blue-black) |
| `--ink` | `#10132e` | `#eeeef1` | Text, the trunk, the transaction line, primary button |
| `--ink-2` / `--ink-3` | `#474d6b` / `#5f6685` | `#b3b4bc` / `#9a9ba4` | Secondary / tertiary text (≥ 4.5:1 on the ground) |
| `--rule` | `#dcdfea` | `#2b2c31` | Hairlines between sections and rows |
| `--vpn` | `#6a3de0` | `#a58bff` | **Through the VPN** — the desktop app's own VPN colour. Only ever means that. |
| `--direct` | `#1a7f37` | `#45c267` | **Direct** — the app's. Also "kept" (the change stays). |
| `--amber` | `#9a6100` | `#e0a43a` | Rolled back |
| `--signal` | `#cf222e` | `#ff7b72` | Panic, and "never" |
| `--ground-2` | `#f2f3f8` | `#16171a` | Admin background only |

The brand mark is the app icon: an indigo rounded square (`#6157f7 → #4338ca`)
with a white fork. Violet is never a button or background colour — it means
"through the VPN".

## Type

- **Go** (Regular 400, Bold 700) for everything; **Go Mono** only for
  addresses, interfaces and domains — never as decoration. Bigelow & Holmes for
  the Go project, BSD-licensed; the notice is at the top of `site.css`.
- Persian falls back to the platform's Arabic-script face (SF Arabic, Segoe UI,
  Noto Sans Arabic). *Open:* a self-hosted Persian face (Vazirmatn, OFL) waits
  on the owner's approval.
- Display: `h1` `clamp(2.6rem, 1.1rem + 4.9vw, 5.6rem)` (5rem in the
  two-column hero), `-0.035em`, line-height ~1; `h2`
  `clamp(2.1rem, 1.3rem + 2.7vw, 3.6rem)`. Persian headings: no negative
  tracking, line-height 1.35–1.4. Body 1.0625rem / 1.6 (Persian 1.9).
- No eyebrows/kickers above headings, no uppercase tracked labels.

## The line grammar (the components)

- **Line:** `--lw` = 10px, round caps, 45° bends (desktop fork is exact:
  rows 132px, junction 96×264). Ends in an arrowhead toward "the internet".
- **Stop (`.stn`):** 22px circle, ground fill, 5px ring in the line's colour
  (`--c`). The origin ("Your computer") is 34px with a 7px ink ring.
- **Legend:** a short bar per line colour and a ring for "a rule".
- **Dashed segment:** planned, not in service (privacy "Later").
- **Buffer stop:** a bar across the end of a line — the line ends here
  (privacy "Never", the kill-switch glyph).
- **Fork:** the same shape everywhere — traffic (VPN / direct), transactions
  (kept / rolled back), and the closing callback.
- **Glyphs** (features index): authored inline SVG, 2.5px stroke, one colour.
- **Buttons:** pill, `--ink` fill, ground-coloured text; hover lightens the ink.
  Secondary actions are underlined text.

## Layout

- Content width 1200px, gutter `clamp(16px, 4vw, 48px)`; the hero map and the
  closing line run full-bleed to the inline end.
- ≥1100px: the hero is two columns (headline | offer), so the whole map fits a
  1440×900 screen. <880px: the map turns downward (S-curve fork, two columns),
  the privacy line turns vertical, the transaction fork branches sideways at
  ≤520px.
- Sections: generous block padding `clamp(80px, 11vw, 144px)`, divided by
  hairline rules — no coloured bands.

## Motion

One authored moment, "the split": a pulse runs the trunk, then one runs each
line while the stops ring as it passes (≥880px); down the trunk and columns on
narrow screens. 6s cycle, three runs, then rest. Nothing moves under
`prefers-reduced-motion`. Content never depends on the animation.

## Rasters and their provenance

- `static/explain-light.png`, `static/explain-dark.png` — screenshots of the
  real RiftRoute desktop UI (Routing Table → "Where does traffic go?" for
  `10.20.30.40`), running in browser-dev mode (`desktop/frontend/src/dev/shim.ts`)
  against `riftrouted -provider fake` with `examples/quickstart.yaml` applied;
  captured at 2× through Chrome DevTools, cropped to the content (ending on a
  row line). `static/explain-narrow-{light,dark}.png` are the same lookup panel
  alone, captured with the app 640px wide (the panel 400px), for screens under
  1100px — served by `<picture>` art direction so the text stays readable.
  Simulated network, real app. Retake them when that screen changes.
- `static/favicon.svg` — the app icon, redrawn as SVG.
