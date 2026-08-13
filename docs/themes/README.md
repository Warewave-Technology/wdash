# Three themes, on the real screens

Examples for the phase-4 question in [ROADMAP.md](../../ROADMAP.md): WDash has
one palette and it is dark. These are what the alternatives look like.

| | |
|---|---|
| [`1-karanlik.jpg`](1-karanlik.jpg) | **Karanlık** — today's, unchanged. The reference to compare against. |
| [`2-acik.jpg`](2-acik.jpg) | **Açık** — a light theme. |
| [`3-yuksek-kontrast.jpg`](3-yuksek-kontrast.jpg) | **Yüksek kontrast** — pure black, brighter accents, outlined chips. |

Each sheet is the same three pages — the monitor list, one monitor's detail,
and the configuration screen — rendered by a real Chromium against a real
running WDash, on a copy of a real database. Not mock-ups: the failing TLS
checks, the 10,022 ms peak and the five configured sources are all things that
happened.

Nothing in `src/`, `static/` or `templates/` was changed to produce them.
`render.py` beside this file rewrites the stylesheet on its way to the browser
and puts the classes back the way a real theme would have to.

## What it cost, measured — and since done

These images were made before any of it, by rewriting the stylesheet on its
way to the browser. Rendering them is what measured the work, and the palette
turned out to be the smaller half:

* **24 fixed-theme Bootstrap classes**, in six templates and three scripts.
  `<body class="bg-dark text-light">` was the important one: `.bg-dark` is a
  FIXED colour with `!important`, so it overrode every token underneath it —
  the first attempt at the light theme produced white cards floating on a
  dark page, and the palette was not the reason. `table table-dark` appeared
  thirteen times and was worse: it pins the text colour too, so on a light
  background the sources table rendered white on white.
* **About a hundred literal colours** — 33 hex and 68 `rgb()`/`rgba()`
  outside `:root` in the stylesheet, against 250 uses of `var()`, plus the
  chart colours in the scripts, which no test about colour had ever read.

Both are done: every colour now comes from the palette, and no template or
script names a theme. `tests/test_contrast.py` fails on either coming back.
One thing the removal exposed is worth knowing — `.bg-dark` on `<body>` had
been painting the page Bootstrap's `#212529` all along, while
`--surface-page` said `#0d1117`. The token and the page disagreed, and the
token lost.

## Contrast, measured

Computed with the project's own `tests.test_contrast.contrast`, which is the
WCAG 2.1 formula. AA for normal text is 4.5:1; AAA is 7:1.

| | Karanlık | Açık | Yüksek kontrast |
|---|---|---|---|
| body text | 17.4:1 | 15.8:1 | 21.0:1 |
| muted text on the page | 6.2:1 | 6.1:1 | 14.4:1 |
| muted text on a card | 5.3:1 | 6.1:1 | 14.4:1 |
| error red | 7.5:1 | 5.4:1 | 9.2:1 |
| success green | 12.3:1 | 7.4:1 | 12.1:1 |
| warning yellow | 12.2:1 | 7.1:1 | 14.9:1 |
| link teal | 9.1:1 | 5.4:1 | 14.5:1 |
| **lowest** | **5.3:1** | **5.4:1** | **9.2:1** |

All three pass AA everywhere measured. Only the high-contrast one passes AAA
everywhere — which is the argument for it existing: not that it looks better,
but that a projector, a bright room and a bad screen are all real.

The light palette is the one to watch. Its accents had to be darkened well
past their dark-theme equivalents to clear AA on white — `#7ee787` green is
1.5:1 on white and unusable, so it became `#116329` at 7.4:1.
A light theme is not the dark one with the background flipped, and the same is
true of the tests: `test_contrast.py` reads one `:root` today and would have
to hold every theme that exists, or it would be checking whichever one
happened to be first.
