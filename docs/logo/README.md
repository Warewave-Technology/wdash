# Three marks

Candidates to replace the navbar's Font Awesome magnifying glass, which is
not a logo — it is an icon the product borrowed, it means "search" on every
other site that uses it, and it says nothing about the two signals WDash has
that a search box does not.

Nothing here is wired into the application. Pick one first.

| | Idea | What it says |
|---|---|---|
| [1](1-pulse-in-brackets.svg) | **Pulse in brackets** | a terminal that watches |
| [2](2-waveform-w.svg) | **Waveform W** | the monogram *is* the chart |
| [3](3-panes.svg) | **Panes** | the dashboard itself |

## How they follow the theme

One file each, no light and dark variants to keep in step. Everything except
one element is `currentColor`, so the mark takes the ink of whatever it sits
in — navbar, tab strip, a filled accent button where the ink is the page
background.

The one element that is not — the pulse, the live point, the sparkline — is
`var(--wdash-accent, #39c5cf)`. Inline the file and the palette decides it;
leave the variable unset and it falls back to the dark theme's cyan.

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
