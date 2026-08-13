# The themes

| | |
|---|---|
| [`1-karanlik.jpg`](1-karanlik.jpg) | **Dark** — the default. What every installation shows until somebody chooses. |
| [`2-acik.jpg`](2-acik.jpg) | **Light** |

The navbar carries a third option, *Follow system*, which is one of these two
depending on the desktop and switches while the page is open.

Each sheet is the same three pages — the monitor list, one monitor's detail,
and the configuration screen — rendered by a real Chromium against a real
running WDash, on a copy of a real database, driving the product's own switch.
`render.py` beside this file is what produced them.

## What it cost, measured before it was built

These started as a question rather than a result. Three palettes were pushed
into the running product by rewriting the stylesheet on its way to the
browser, to find out what a theme would actually take — and the palette turned
out to be the smaller half:

* **24 fixed-theme Bootstrap classes**, in six templates and three scripts.
  `<body class="bg-dark text-light">` was the important one: `.bg-dark` is a
  FIXED colour with `!important`, so it overrode every token underneath it —
  the first attempt at the light theme produced white cards floating on a
  dark page, and the palette was not the reason. `table table-dark` appeared
  thirteen times and was worse: it pins the text colour too, so on a light
  background the sources table rendered white on white.
* **About a hundred literal colours** — 33 hex and 68 `rgb()`/`rgba()`
  outside `:root` in the stylesheet, against 250 uses of `var()`, plus the
  chart colours in the scripts, which no test about colour had ever read. The
  gridlines were `#30363d`, a shade of a dark background, invisible on white.

So the order of work was: name the tokens for their role, move every colour
into the palette, take the fixed classes out of the templates, and only then
add a theme. `tests/test_contrast.py` fails on any of it coming back.

One thing the removal exposed is worth keeping: `.bg-dark` on `<body>` had
been painting the page Bootstrap's `#212529` all along, while `--surface-page`
said `#0d1117`. The token and the page disagreed for as long as both existed,
and the page won.

## Contrast, measured

Computed with the project's own `tests.test_contrast.contrast`, which is the
WCAG 2.1 formula. AA for normal text is 4.5:1.

| | Dark | Light |
|---|---|---|
| body text | 17.4:1 | 15.8:1 |
| muted text on a card | 5.3:1 | 6.1:1 |
| error red | 7.5:1 | 6.6:1 |
| success green | 12.3:1 | 7.4:1 |
| link teal | 9.1:1 | 5.4:1 |

Every value in both palettes is measured by the suite, not by this table: the
measuring test classes take their palette from a class attribute and are
generated once per theme in the stylesheet, so a third theme is measured by
all of them the day it is added.

A light theme is not the dark one with the background flipped. Its accents had
to be darkened well past their dark-theme equivalents — the success green is
`#7ee787` at 1.5:1 on white — and the red had to go darker still, because
`#cf222e` measures 4.40:1 against its own 12% tint on a white card, which is
where the expiry chip and the down-row wash put it.

What does NOT change between themes is as deliberate: the `--fill-*` colours
and `--text-on-fill`. A chip is a bright shape with dark text on it, and that
reads on white as well as it reads on black.
