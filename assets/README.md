# README assets

Generated imagery for the project README (built with Claude Design, matched to
the console palette — slate `#0f172a`, emerald / amber / red, no baked-in text).

| File | Used as | Size |
|---|---|---|
| `hero.png` | Top-of-README hero banner | 1600×760 |
| `architecture.png` | Architecture-section diagram | 1400×1000 |
| `explainer.png` | Three-verdict cards in "How it works" | 1400×480 |
| `usage-flow.png` | Four-step usage strip in "How it works" | 1600×480 |
| `faq-banner.png` | Header banner in `docs/FAQ.md` | 1600×420 |

`usage-flow` and `faq-banner` are hand-authored SVG (editable source committed
alongside as `*.svg`) rasterized to PNG with `@resvg/resvg-js`. To re-render
after editing the SVG:

```bash
npx @resvg/resvg-js  # or a one-off node script using { fitTo: { mode: 'width', value: 1600 } }
```

## Generating with Claude Design

- Ask for a **transparent or solid `#0f172a` background** so the image sits
  cleanly on GitHub's dark theme.
- Generated images render text as garbled glyphs — ask Claude Design to **omit
  words**, and rely on the README's own headings/labels for text.
- Keep the palette to the three verdict colors: emerald (ALLOW), amber (HOLD),
  red (DENY).
