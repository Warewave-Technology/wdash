# The themes

| | |
|---|---|
| [`1-karanlik.jpg`](1-karanlik.jpg) | **Gruvbox dark** — the default. What every installation shows until somebody chooses. |
| [`2-acik.jpg`](2-acik.jpg) | **Gruvbox light** |

Both are [Gruvbox](https://github.com/morhetz/gruvbox) at its medium
contrast, with orange as the one accent. They replaced a dark and a light
palette of the product's own; the tokens stayed where they were, so the
change was the two `:root` blocks in `static/css/wdash.css` and nothing
underneath them.

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
| body text | 10.7:1 | 10.2:1 |
| muted text on a card | 6.0:1 | 8.0:1 |
| error red | 6.2:1 | 7.6:1 |
| success green | 7.1:1 | 5.5:1 |
| link orange | 5.8:1 | 5.5:1 |

Lower than the palettes before, and that is Gruvbox rather than a slip: it
is a low-contrast scheme on purpose, cream on warm grey. Everything still
clears 4.5:1 where it lands.

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

## Where Gruvbox had to give

Gruvbox's values are used wherever they clear 4.5:1 on every surface they
land on. Where one does not, it is moved the least distance that does,
keeping its hue and saturation. Measured, and each one is commented beside
its token:

| token | theme | Gruvbox | used | why |
|---|---|---|---|---|
| `--text-secondary` | dark | fg4 `#a89984` | `#afa089` | 4.17:1 on a raised surface; 31% of the way to fg3 clears it |
| `--hue-red`, `--fill-red` | dark | `#fb4934` | `#fc8678` | 3.37:1 on a raised surface, 4.24:1 on its own 12% tint in an expiry chip |
| `--hue-blue`, `--hue-purple` | dark | `#83a598`, `#d3869b` | `#88a99c`, `#d58da1` | under 4.5:1 on a raised surface by a hair; under 2% of lightness |
| `--text-on-fill` | both | bg0 `#282828` | bg0_h `#1d2021` | Gruvbox's red fill is 4.29:1 under bg0, 4.77:1 under bg0_h |
| `--fill-*-vivid` | both | neutral shades | orange, blue, purple lifted | a gradient's far end carries text too; three neutral shades failed under `--text-on-fill` |
| `--accent` | light | `#af3a03` | `#ad3a03` | 4.46:1 on a raised surface |
| `--hue-green` | light | `#79740e` | `#68630c` | 3.55:1 on a raised surface |
| `--hue-cyan` | light | `#427b58` | `#3a6b4d` | 3.64:1 on a raised surface |
| `--hue-yellow` | light | `#b57614` | `#86570f` | 2.75:1 on a raised surface — the furthest move; a yellow a reader can read on cream is nearer brown than yellow |

The charts follow too. A canvas is painted once, with the colours of the
moment it was drawn in, so every chart listens for the theme switch and is
drawn again from what is already on the page: the log histogram, the
dashboard's panels, a monitor's response chart. The histogram's axis and
legend text had been left to Chart.js's own `#666`, 2.2:1 on the dark page,
where no stylesheet check could see it.
