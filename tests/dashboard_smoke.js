/**
 * Runtime smoke test for the dashboard bundle.
 *
 * The panel spinner is an overlay laid over the chart area, removed at the END
 * of `renderPanel`. Three early returns skip that line — no data in the
 * window, a panel whose own source failed, and a drawing error — so the exact
 * cases that most need explaining were the ones that kept spinning. Choosing a
 * time range with no logs in it left every panel loading for ever.
 *
 * None of that is a syntax error. Only running the code against a DOM finds
 * it, which is what this does.
 *
 * Run: npm test        (or: node tests/dashboard_smoke.js)
 */

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const ROOT = path.join(__dirname, '..');
const failures = [];

function check(name, fn) {
    if (typeof fn !== 'function') {
        throw new Error(`check("${name}") was given a ${typeof fn}, not a function`);
    }
    try {
        fn();
        console.log(`  ok    ${name}`);
    } catch (e) {
        failures.push(`${name}: ${e.message}`);
        console.log(`  FAIL  ${name}\n        ${e.message}`);
    }
}

function assert(condition, message) {
    if (!condition) throw new Error(message);
}

// --- a DOM with the pieces dashboard_view.html provides -------------------

function makeDashboard(responder) {
    const dom = new JSDOM(`<!doctype html><body>
        <span id="totalHits"></span><span id="errorCount"></span>
        <span id="warnCount"></span><span id="infoCount"></span>
        <span id="lastUpdated"></span>
        <select id="timeRange"><option value="1h" selected>1h</option></select>
        <input id="dashboardFilter" value="">
        <div id="panelGrid"></div>
        <template id="panelTemplate">
            <div class="col-md-6 panel-slot">
                <div class="card h-100">
                    <div class="card-header">
                        <h5 class="mb-0 panel-title"></h5>
                        <small class="panel-hint"></small>
                    </div>
                    <div class="card-body">
                        <div class="chart-container" style="height:300px">
                            <canvas></canvas>
                        </div>
                        <div class="panel-empty text-center text-muted d-none py-5">
                            <div class="mt-2"><small>No data in this window</small></div>
                        </div>
                    </div>
                </div>
            </div>
        </template>
        </body>`, { runScripts: 'outside-only', url: 'http://localhost/dashboards/d1' });

    const w = dom.window;
    global.window = w;
    global.document = w.document;
    global.fetch = w.fetch = responder;

    // Chart.js is loaded from a CDN in the page and is not the subject here.
    // A stub that records nothing still exercises every line around it.
    // Faithful in the two ways the bundle depends on: a real Chart instance
    // exposes `.config`, which `upsertChart` reads to decide between updating
    // in place and rebuilding. A stub without it throws on every SECOND
    // render — which looked like a spinner bug and was not.
    function ChartStub(context, config) {
        return {
            config: config || {},
            data: (config || {}).data,
            options: (config || {}).options,
            destroy() {}, update() {},
        };
    }
    // `Chart.defaults` is written to at start-up; without it the constructor
    // throws and every panel case below would fail for the wrong reason.
    ChartStub.defaults = { color: null, borderColor: null };
    w.Chart = global.Chart = ChartStub;
    w.toastManager = { success() {}, warning() {}, error() {} };

    // jsdom has no canvas. Chart.js only ever asks for a 2d context, and the
    // stub above ignores it — but an unstubbed getContext THROWS, which would
    // send every populated panel down the drawing-error path and make the
    // "still draws" checks pass for the wrong reason.
    w.HTMLCanvasElement.prototype.getContext = () => ({});

    const source = fs.readFileSync(
        path.join(ROOT, 'static/js/async-dashboard.js'), 'utf8');
    // A top-level `class` binding from an indirect eval does not outlive the
    // call and never becomes a property of `window`. The page loads this as a
    // <script>, where it would; here the export is appended so the SAME eval
    // can see the binding and hand it out.
    w.eval(source + '\n;window.AsyncDashboard = AsyncDashboard;');
    return w;
}

/** A response shaped like /api/dashboard/<id>/data. */
function jsonResponse(body, ok = true, status = 200) {
    return async () => ({ ok, status, json: async () => body });
}

const PANEL = {
    id: 'p1', title: 'Levels', type: 'terms', width: 6,
};

function spinning(w) {
    return w.document.querySelectorAll(
        '.chart-loading-overlay, #panelGrid .grid-loading').length;
}

/** Wait until no load is in flight.
 *
 * The constructor starts one, and `load()` returns immediately while another
 * is running — so awaiting our own call proves nothing. Without this the
 * assertions ran against a half-built page and reported failures the browser
 * would never show.
 */
async function settle(dashboard) {
    for (let i = 0; i < 200 && dashboard.loading; i++) {
        await new Promise(resolve => setImmediate(resolve));
    }
    if (dashboard.loading) throw new Error('a load never finished');
}

async function loadWith(body, { ok = true, status = 200 } = {}) {
    const w = makeDashboard(jsonResponse(body, ok, status));
    const dashboard = new w.AsyncDashboard('d1');
    await settle(dashboard);
    await dashboard.load();
    await settle(dashboard);
    w.dashboard = dashboard;
    return w;
}

async function main() {
    console.log('\ndashboard panel rendering\n');

    // The reported fault, exactly: a window with nothing in it.
    const empty = await loadWith({
        total_hits: 0, error_count: 0, warn_count: 0, info_count: 0,
        panels: [{ ...PANEL, buckets: [] }],
    });
    check('a window with no data stops spinning', () =>
        assert(spinning(empty) === 0,
               `${spinning(empty)} spinner(s) still on screen`));
    check('a window with no data says so', () => {
        const message = empty.document.querySelector('.panel-empty small');
        assert(message && !message.closest('.panel-empty').classList.contains('d-none'),
               'the empty-state message is hidden');
    });

    // All-zero buckets: the axis is drawn but nothing happened. Same path.
    const zeroes = await loadWith({
        panels: [{ ...PANEL, type: 'timeseries',
                   buckets: [{ key: '10:00', count: 0 }, { key: '11:00', count: 0 }] }],
    });
    check('an all-zero series stops spinning', () =>
        assert(spinning(zeroes) === 0, `${spinning(zeroes)} spinner(s) left`));

    // A panel whose own backend failed.
    const broken = await loadWith({
        panels: [{ ...PANEL, error: 'lab-loki: connection refused' }],
    });
    check('a failed panel stops spinning', () =>
        assert(spinning(broken) === 0, `${spinning(broken)} spinner(s) left`));
    check('a failed panel shows the reason', () => {
        const text = broken.document.querySelector('.panel-empty small').textContent;
        assert(/connection refused/.test(text), `message was "${text}"`);
    });

    // A panel the browser could not draw.
    const undrawable = await loadWith({
        panels: [{ ...PANEL, type: 'timeseries', buckets: 'not-an-array' }],
    });
    check('an undrawable panel stops spinning', () =>
        assert(spinning(undrawable) === 0, `${spinning(undrawable)} spinner(s) left`));

    // The grid-wide spinner on a first load that yields no panels at all.
    const nothing = await loadWith({ panels: [] });
    check('no panels at all stops the grid spinner', () =>
        assert(spinning(nothing) === 0, `${spinning(nothing)} spinner(s) left`));

    // And the case that must NOT change: real data still draws.
    const populated = await loadWith({
        total_hits: 12,
        panels: [{ ...PANEL, buckets: [{ key: 'ERROR', count: 12 }] }],
    });
    check('a panel with data still draws', () => {
        assert(spinning(populated) === 0, 'spinner left over a drawn panel');
        const container = populated.document.querySelector('.chart-container');
        assert(!container.classList.contains('d-none'), 'chart area was hidden');
    });

    // A second load must not leave the first load's overlay behind either.
    const refreshed = await loadWith({
        panels: [{ ...PANEL, buckets: [{ key: 'ERROR', count: 1 }] }],
    });
    global.fetch = refreshed.fetch = jsonResponse({ panels: [{ ...PANEL, buckets: [] }] });
    await refreshed.dashboard.load();
    await settle(refreshed.dashboard);
    check('going from data to no data stops spinning', () =>
        assert(spinning(refreshed) === 0, `${spinning(refreshed)} spinner(s) left`));

    // The request itself failing. A different path — showLoadError, not
    // render — so the invariant has to hold there too.
    const rejected = await loadWith(
        { error: "Invalid filter: unbalanced quote" }, { ok: false, status: 400 });
    check('a rejected request stops spinning', () =>
        assert(spinning(rejected) === 0, `${spinning(rejected)} spinner(s) left`));
    check('a rejected request says the panels did not load', () => {
        const text = rejected.document.getElementById('panelGrid').textContent;
        assert(/could not be loaded/i.test(text), `grid said "${text.trim()}"`);
    });
    check('a rejected filter marks the filter box', () => {
        const filter = rejected.document.getElementById('dashboardFilter');
        assert(filter.classList.contains('is-invalid'),
               'the filter box was not marked, so a typo reads as a broken dashboard');
    });

    // The case the first-load error test cannot reach: panels are ON SCREEN
    // when the next load fails. Those slots get a fresh overlay from
    // showAllLoadingStates, and only showLoadError's per-slot sweep takes
    // them off — a dashboard someone is watching, one bad filter, every
    // panel spinning over the data it is still showing.
    const wasShowing = await loadWith({
        panels: [{ ...PANEL, buckets: [{ key: 'ERROR', count: 3 }] }],
    });
    assert(wasShowing.document.querySelectorAll('.panel-slot').length === 1,
           'the setup for this check did not draw a panel');
    global.fetch = wasShowing.fetch = jsonResponse(
        { error: 'Invalid filter: unbalanced quote' }, false, 400);
    await wasShowing.dashboard.load();
    await settle(wasShowing.dashboard);
    check('a failure over drawn panels stops spinning', () =>
        assert(spinning(wasShowing) === 0, `${spinning(wasShowing)} spinner(s) left`));
    check('a failure over drawn panels keeps them on screen', () =>
        assert(wasShowing.document.querySelectorAll('.panel-slot').length === 1,
               'the panels were thrown away, so the last good data is gone too'));

    // A server that answers 200 with an explanation and no panels: not an
    // error, but it still has to stop.
    const explained = await loadWith(
        { error: 'No accessible indices for this dashboard.', panels: [] });
    check('an explained empty response stops spinning', () =>
        assert(spinning(explained) === 0, `${spinning(explained)} spinner(s) left`));

    // ---------------------------------------------------------------------
    // Chart colours come from the palette
    // ---------------------------------------------------------------------
    //
    // The chart used to paint with colours written into this file: gridlines
    // at `#30363d`, which is a shade of a dark page background and vanishes
    // on a light one. Nothing about colour had ever looked at a script, so
    // the stylesheet could be themed down to the last token and the charts
    // would still be drawn for the theme they were written in.
    const palette = makeDashboard(jsonResponse({ panels: [] }));
    // `--fill-red`, not `--hue-red`: a chart bar is a shape somebody reads a
    // label against, so it takes the FILL. The ink hue goes dark on a light
    // theme and would paint a near-black bar.
    palette.document.documentElement.style.setProperty('--fill-red', '#abcdef');
    palette.document.documentElement.style.setProperty('--border', '#123456');
    palette.document.documentElement.style.setProperty('--text-muted', '#654321');
    palette.document.documentElement.style.setProperty(
        '--chart-series', '#111111, #222222, #333333');

    check('a severity takes its colour from the palette', () =>
        assert(palette.AsyncDashboard.seriesColour('ERROR', 0) === '#abcdef',
               `got ${palette.AsyncDashboard.seriesColour('ERROR', 0)}`));

    check('an unknown series walks the palette ramp', () => {
        const first = palette.AsyncDashboard.seriesColour('checkout', 0);
        const third = palette.AsyncDashboard.seriesColour('billing', 2);
        assert(first === '#111111' && third === '#333333',
               `ramp gave ${first} and ${third}`);
    });

    check('the ramp wraps rather than running out', () =>
        assert(palette.AsyncDashboard.seriesColour('n', 4) === '#222222',
               'index 4 of a three-colour ramp should be the second'));

    check('the axis takes its gridlines from the palette', () => {
        const axis = palette.AsyncDashboard.axisStyle();
        assert(axis.grid.color === '#123456' && axis.ticks.color === '#654321',
               `axis used ${axis.grid.color} / ${axis.ticks.color}`);
    });

    console.log('');
    if (failures.length) {
        console.log(`${failures.length} dashboard check(s) failed\n`);
        process.exit(1);
    }
    console.log('all dashboard checks passed\n');
}

main().catch(e => { console.error(e); process.exit(1); });
