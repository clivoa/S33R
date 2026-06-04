# S33R — Handoff de integração da marca

Pacote com a identidade **SEER** — o vidente encapuzado de um olho. Abaixo, exatamente o que aplicar no repo. Substitui a pasta `brand/` antiga (que usava o olho/mira).

## 1. Adicionar a pasta `brand/`

Copie a pasta `brand/` inteira para a **raiz do repo** (no site Jekyll ela já fica acessível em `/brand/`).

```
brand/
├── seer-mark.svg          símbolo isolado, full-color (capuz + barba + olho)
├── logo.svg               lockup símbolo + wordmark (tema escuro)
├── logo-light.svg         lockup para fundo claro
├── favicon.svg            favicon vetorial (tile âmbar + Seer em tinta)
├── favicon-16.png         favicon 16×16
├── favicon-32.png         favicon 32×32
├── favicon-48.png         favicon 48×48
├── apple-touch-icon.png   ícone iOS 180×180
├── readme-banner.png      banner 2560×640 (@2x) para o topo do README
└── README.md              ficha da marca / snippets
```

## 2. Banner no README do repo

No topo do `README.md` principal:

```markdown
<p align="center">
  <img src="brand/readme-banner.png" alt="S33R — Security Intelligence Feed" width="100%" />
</p>
```

## 3. Favicon no `<head>` de cada página

**Páginas standalone (`*.html`):**
```html
<link rel="icon" type="image/svg+xml" href="brand/favicon.svg" />
<link rel="icon" type="image/png" sizes="32x32" href="brand/favicon-32.png" />
<link rel="icon" type="image/png" sizes="16x16" href="brand/favicon-16.png" />
<link rel="apple-touch-icon" href="brand/apple-touch-icon.png" />
```

**Páginas Jekyll (usam `relative_url`):**
```html
<link rel="icon" type="image/svg+xml" href="{{ '/brand/favicon.svg' | relative_url }}" />
<link rel="icon" type="image/png" sizes="32x32" href="{{ '/brand/favicon-32.png' | relative_url }}" />
<link rel="icon" type="image/png" sizes="16x16" href="{{ '/brand/favicon-16.png' | relative_url }}" />
<link rel="apple-touch-icon" href="{{ '/brand/apple-touch-icon.png' | relative_url }}" />
```

## 4. Trocar o ícone do rail pelo Seer encapuzado

O rail é montado em **`s33r-nav.js`**. O chip `.rail-logo` é âmbar com conteúdo em tinta — então o Seer entra como silhueta `currentColor` e o **olho é um furo** (`fill-rule:evenodd`) por onde o âmbar do chip aparece e "acende".

**(a)** adicione/atualize o ícone `seer` no objeto `ICONS` (viewBox 64):
```js
seer: '<path fill="currentColor" fill-rule="evenodd" d="M11 59 C11 30 17 6 32 6 C47 6 53 30 53 59 Z M37 22 a3 3 0 1 0 0 6 a3 3 0 1 0 0 -6 Z"/>',
```

**(b)** troque o `<a class="rail-logo">` para usar o novo ícone (note `fill`, sem `stroke`):
```js
`<a class="rail-logo" href="${hrefFor("S33R Feed.html", "")}" title="S33R — the SEER"><svg width="26" height="26" viewBox="0 0 64 64">${ICONS.seer}</svg></a>`
```

Para páginas com o rail **inline** (ex.: `index.html` da home), substitua o SVG dentro de `.rail-logo` / `.nav-brand` pelo mesmo conteúdo do `seer` (viewBox `0 0 64 64`, `fill`).

## 5. Cores

| Token | Valor |
|---|---|
| Âmbar (brand) — tema escuro | `#f5a623` |
| Âmbar (brand) — tema claro | `#c9790a` |
| Ink (sobre âmbar) | `#1b1304` |
| Capuz / barba / sombra (mark full-color) | `#37425a` · `#e8edf4` · `#0c0f16` |
| Fundo escuro | `#080a0e` |

> Obs.: o favicon usa o Seer em tinta sobre tile âmbar com o olho âmbar destacado — lê bem de 48px a 16px. **Um só olho acende; nada de multiplicar cores quentes.**
