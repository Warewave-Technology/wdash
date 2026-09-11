# Three marks

Candidates to replace the navbar's Font Awesome magnifying glass, which is
not a logo — it is an icon the product borrowed, it means "search" on every
other site that uses it, and it says nothing about the two signals WDash has
that a search box does not.

**1 is the one in use** — the navbar and the favicon carry it. The other two
stay here because a choice with nothing beside it is not a choice, and the
next person to argue for changing it should be arguing against something.

| | Idea | What it says |
|---|---|---|
| [1](1-pulse-in-brackets.svg) ← | **Pulse in brackets** | a terminal that watches |
| [2](2-waveform-w.svg) | **Waveform W** | the monogram *is* the chart |
| [3](3-panes.svg) | **Panes** | the dashboard itself |

## How they follow the theme

One file each, no light and dark variants to keep in step. Everything except
one element is `currentColor`, so the mark takes the ink of whatever it sits
in — navbar, tab strip, a filled accent button where the ink is the page
background.

The one element that is not — the pulse, the live point, the sparkline — is
`var(--wdash-accent, #fe8019)`. Inline the file and the palette decides it;
leave the variable unset and it falls back to Gruvbox's orange, the dark
theme's accent.

Each file also carries an id-scoped `<style>` giving `color` a value under
`prefers-color-scheme`, which only does anything when the file is opened on
its own or used as an `<img>`. It is scoped to the mark's own id on purpose:
an unscoped `svg { color: … }` would reach every SVG on the page it was
inlined into, and this product draws its sparklines in SVG.

## What they were checked against

Rendered at 96px, at the navbar's 26px, and at a browser tab's 16px, on both
themes and on an accent fill — open `candidates.html` beside this file, which
also has a switch that takes the accent away. A mark that needs two colours
to work is a mark that breaks in a favicon.

The first version of the pulse had four peaks of similar height, which at 16
pixels is texture rather than a shape; it is one heartbeat now.

A mark that only works large is a mark somebody sees once, in the README.

## Where it is used

| | |
|---|---|
| `templates/base.html` | the navbar, inline, so the brackets take the bar's ink and the pulse takes `--accent` |
| `static/img/wdash-mark.svg` | the favicon, with its own `prefers-color-scheme` rule — a browser fetches it on its own and it inherits nothing |
| `static/img/wdash-mark-32.png` | the fallback for browsers that will not take an SVG here |

Three copies of one drawing drift, and the only symptom is a tab icon that
has quietly stopped being the logo. `tests/test_frontend_integrity.py`
compares the path data in all three.

The PNG is one colour, `#c35d1a`, and that number was measured rather than
picked: 4.28:1 against a white tab strip, 3.76:1 against a dark one and
3.27:1 against a light-grey one — a shade of Gruvbox's orange, because the
accent itself cannot do it: bright orange is 2.53:1 on white, the faded one
2.63:1 on dark chrome. `render_png.py` beside this file draws it from the SVG
favicon, so the two cannot disagree about the shape.

`.navbar-brand` is accent-coloured, so `currentColor` inside it *is* the
accent: without `.navbar-brand .wdash-mark { color: var(--text-primary) }`
the whole drawing comes out orange and the pulse disappears into it.
