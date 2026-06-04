# S33R - Brand Integration Handoff

Package with the **SEER** identity - the one-eyed hooded seer. Below is exactly what to apply in the repo. It replaces the old `brand/` folder, which used the eye/target mark.

## 1. Add the `brand/` folder

Copy the entire `brand/` folder to the **repo root**. On the Jekyll site, it will already be available at `/brand/`.

```
brand/
├── seer-mark.svg          standalone full-color symbol (hood + beard + eye)
├── logo.svg               symbol + wordmark lockup for dark themes
├── logo-light.svg         lockup for light backgrounds
├── favicon.svg            vector favicon (amber tile + ink Seer)
├── favicon-16.png         favicon 16×16
├── favicon-32.png         favicon 32×32
├── favicon-48.png         favicon 48×48
├── apple-touch-icon.png   iOS icon 180×180
├── readme-banner.png      2560×640 (@2x) banner for the top of the README
└── README.md              brand sheet / snippets
```

## 2. Repo README Banner

At the top of the main `README.md`:

```markdown
<p align="center">
  <img src="brand/readme-banner.png" alt="S33R — Security Intelligence Feed" width="100%" />
</p>
```

## 3. Favicon in each page `<head>`

**Standalone pages (`*.html`):**
```html
<link rel="icon" type="image/svg+xml" href="brand/favicon.svg" />
<link rel="icon" type="image/png" sizes="32x32" href="brand/favicon-32.png" />
<link rel="icon" type="image/png" sizes="16x16" href="brand/favicon-16.png" />
<link rel="apple-touch-icon" href="brand/apple-touch-icon.png" />
```

**Jekyll pages (use `relative_url`):**
```html
<link rel="icon" type="image/svg+xml" href="{{ '/brand/favicon.svg' | relative_url }}" />
<link rel="icon" type="image/png" sizes="32x32" href="{{ '/brand/favicon-32.png' | relative_url }}" />
<link rel="icon" type="image/png" sizes="16x16" href="{{ '/brand/favicon-16.png' | relative_url }}" />
<link rel="apple-touch-icon" href="{{ '/brand/apple-touch-icon.png' | relative_url }}" />
```

## 4. Replace the rail icon with the hooded Seer

The rail is assembled in **`s33r-nav.js`**. The `.rail-logo` chip is amber with ink content, so the Seer enters as a `currentColor` silhouette and the **eye is a cutout** (`fill-rule:evenodd`) where the chip's amber shows through and "lights up".

**(a)** Add/update the `seer` icon in the `ICONS` object (viewBox 64):
```js
seer: '<path fill="currentColor" fill-rule="evenodd" d="M11 59 C11 30 17 6 32 6 C47 6 53 30 53 59 Z M37 22 a3 3 0 1 0 0 6 a3 3 0 1 0 0 -6 Z"/>',
```

**(b)** Replace the `<a class="rail-logo">` with the new icon (note `fill`, no `stroke`):
```js
`<a class="rail-logo" href="${hrefFor("S33R Feed.html", "")}" title="S33R — the SEER"><svg width="26" height="26" viewBox="0 0 64 64">${ICONS.seer}</svg></a>`
```

For pages with the rail **inline** (for example, the home `index.html`), replace the SVG inside `.rail-logo` / `.nav-brand` with the same `seer` content (viewBox `0 0 64 64`, `fill`).

## 5. Colors

| Token | Value |
|---|---|
| Amber (brand) - dark theme | `#f5a623` |
| Amber (brand) - light theme | `#c9790a` |
| Ink (on amber) | `#1b1304` |
| Hood / beard / shadow (full-color mark) | `#37425a` · `#e8edf4` · `#0c0f16` |
| Dark background | `#080a0e` |

> Note: the favicon uses the Seer in ink over an amber tile, with the amber eye highlighted. It reads clearly from 48px down to 16px. **Only one eye lights up; do not multiply warm colors.**
