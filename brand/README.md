<!-- S33R brand kit -->
<p align="center">
  <img src="brand/readme-banner.png" alt="S33R — Security Intelligence Feed" width="100%" />
</p>

# S33R - Brand Kit

**The SEER.** S33R is leet for *SEER* (the one who sees). The brand is **a hooded seer** - a guardian of knowledge who reads the signals before others do. A geometric hood silhouette, pale beard, and **one glowing amber eye** (`#f5a623`) on a dark background (`#080a0e`). No target, no shield, no lock - the character *is* the identity. Monospace wordmark, aligned with the UI.

## Files

| File | Usage |
|---|---|
| `readme-banner.png` | Top README banner (2560×640 @2x) |
| `seer-mark.svg` | Standalone full-color symbol (hood + beard + eye) |
| `logo.svg` | Symbol + wordmark lockup for dark themes |
| `logo-light.svg` | Lockup for light backgrounds |
| `favicon.svg` | Vector favicon (amber tile + ink Seer) |
| `favicon-16.png` / `favicon-32.png` / `favicon-48.png` | Raster favicons |
| `apple-touch-icon.png` | iOS icon (180×180) |

## README Banner

```markdown
<p align="center">
  <img src="brand/readme-banner.png" alt="S33R" width="100%" />
</p>
```

## Favicon in `<head>`

```html
<link rel="icon" type="image/svg+xml" href="brand/favicon.svg" />
<link rel="icon" type="image/png" sizes="32x32" href="brand/favicon-32.png" />
<link rel="icon" type="image/png" sizes="16x16" href="brand/favicon-16.png" />
<link rel="apple-touch-icon" href="brand/apple-touch-icon.png" />
```

## Colors

- Amber (brand): `#f5a623` - use `#c9790a` on light themes
- Eye / accent: amber `#f5a623` (the only warm color point)
- Hood (dark): `#37425a` · Beard: `#e8edf4` · Face shadow: `#0c0f16`
- Ink (on amber): `#1b1304`
- Dark background: `#080a0e`

> **Golden rule:** one - and only one - amber eye lights up. The rest of the mascot stays neutral. Do not multiply warm accent colors.
