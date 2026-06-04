# S33R - Brand Integration Handoff

Package with the **SEER** identity (surveillance eye). Below is exactly what to apply in the repo.

## 1. Add the `brand/` folder

Copy the entire `brand/` folder to the **repo root**. In the Jekyll site, it will be available at `/brand/`.

```
brand/
├── seer-mark.svg          standalone symbol (amber, editable)
├── logo.svg               symbol + wordmark lockup (dark theme)
├── logo-light.svg         lockup for light backgrounds
├── favicon.svg            vector favicon (amber tile + eye)
├── favicon-16.png         favicon 16×16 (simplified version)
├── favicon-32.png         favicon 32×32
├── favicon-48.png         favicon 48×48
├── apple-touch-icon.png   iOS icon 180×180
├── readme-banner.png      1280×320 banner (@2x) for the README top
└── README.md              brand sheet / snippets
```

## 2. Repo README banner

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

**Jekyll pages (using `relative_url`):**
```html
<link rel="icon" type="image/svg+xml" href="{{ '/brand/favicon.svg' | relative_url }}" />
<link rel="icon" type="image/png" sizes="32x32" href="{{ '/brand/favicon-32.png' | relative_url }}" />
<link rel="icon" type="image/png" sizes="16x16" href="{{ '/brand/favicon-16.png' | relative_url }}" />
<link rel="apple-touch-icon" href="{{ '/brand/apple-touch-icon.png' | relative_url }}" />
```

## 4. Replace the shield with the SEER eye in the rail

The rail is mounted in **`s33r-nav.js`**. Two changes:

**(a)** add the `seer` icon to the `ICONS` object:
```js
seer: '<path d="M7 32 C18 18 46 18 57 32 C46 46 18 46 7 32 Z" fill="none" stroke="currentColor" stroke-width="3.6" stroke-linejoin="round"/><circle cx="32" cy="32" r="9.5" fill="none" stroke="currentColor" stroke-width="3.6"/><path d="M32 32 L32 22.5 A9.5 9.5 0 0 1 40.7 27.6 Z" fill="currentColor"/><circle cx="32" cy="32" r="3.4" fill="currentColor"/>',
```

**(b)** replace the `<a class="rail-logo">` so it uses the new icon (viewBox 64):
```js
`<a class="rail-logo" href="${hrefFor("S33R Feed.html", "")}" title="S33R — the SEER"><svg width="25" height="25" viewBox="0 0 64 64" fill="none" stroke-linecap="round">${ICONS.seer}</svg></a>`
```

For pages with an **inline** rail (for example the home `index.html`), replace the shield SVG inside `.rail-logo` / `.nav-brand` with the same `seer` content (viewBox `0 0 64 64`).

## 5. Colors

| Token | Value |
|---|---|
| Amber (brand) - dark theme | `#f5a623` |
| Amber (brand) - light theme | `#c9790a` |
| Ink (on amber) | `#1b1304` |
| Dark background | `#080a0e` |

> Note: the 16px favicon uses a minimal eye drawing (without reticle/ring) so it reads well at that size; 32px+ show the full mark.
