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
        <span id="errorRate"></span>
        <div id="totalHitsDelta"></div><div id="errorCountDelta"></div>
        <div id="warnCountDelta"></div><div id="infoCountDelta"></div>
        <div id="baselineNote"></div>
        <span id="lastUpdated"></span>
        <select id="timeRange"><option value="1h" selected>1h</option></select>
        <input id="dashboardFilter" value="">
        <div id="dashboardMessage" class="alert d-none"></div>
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
    // `monitorUrl` goes out with it: it is a module-level function the page
    // never needs by name, and the only way to hold it to the route's own
    // converter here is to be able to call it.
    w.eval(source + '\n;window.AsyncDashboard = AsyncDashboard;'
                  + '\n;window.monitorUrl = monitorUrl;');
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

    // The REASON, which never reached the reader. showLoadError handed the
    // message to window.toastManager, and nothing in static/ or templates/
    // defines one — the stub that used to sit in this file was the only
    // toastManager anywhere, so this suite could not see the gap. A dashboard
    // over a query the backend cannot express drew "Failed to load" above a
    // grid saying the panels could not be loaded, and said no more than that.
    const REFUSAL = 'Range has no LogsQL equivalent; VictoriaLogs cannot ' +
        'express this query';
    // The sentence and the warnings are deliberately different text: the
    // warnings travel on the body, which the thrown error used to discard,
    // so a check that accepted either would pass without them.
    const refused = await loadWith(
        { error: 'The query did not run.', error_type: 'query_failed',
          warnings: [REFUSAL] },
        { ok: false, status: 502 });
    check('a refused query says why, on the page', () => {
        const box = refused.document.getElementById('dashboardMessage');
        assert(/The query did not run/.test(box.textContent),
               `the page said "${refused.document.body.textContent.trim()}"`);
        assert(!box.classList.contains('d-none'), 'the message box stayed hidden');
    });
    check('and the reason travels with it', () => {
        const items = [...refused.document.querySelectorAll('#dashboardMessage li')]
            .map(item => item.textContent);
        assert(items.some(text => /VictoriaLogs cannot express/.test(text)),
               `the warnings on screen were ${JSON.stringify(items)}`);
    });

    // And it has to go away again: a message left standing over a good load
    // describes a page that is no longer on screen.
    global.fetch = refused.fetch = jsonResponse({
        total_hits: 3,
        panels: [{ ...PANEL, buckets: [{ key: 'ERROR', count: 3 }] }],
    });
    await refused.dashboard.load();
    await settle(refused.dashboard);
    check('a later good load clears the message', () => {
        const box = refused.document.getElementById('dashboardMessage');
        assert(box.classList.contains('d-none'),
               `it still said "${box.textContent.trim()}"`);
    });

    // A 200 carrying an explanation instead of data: not an error, but the
    // reader still has to be told, and this went to the same toast manager.
    const explainedAloud = await loadWith(
        { error: 'No accessible indices for this dashboard.', panels: [] });
    check('an explained empty response says so on the page', () => {
        const text = explainedAloud.document
            .getElementById('dashboardMessage').textContent;
        assert(/No accessible indices/.test(text), `the page said "${text}"`);
    });

    // How loudly the page says it. A board whose log source is down answers
    // 200 now — so that the trace panel beside it is drawn — and that moved
    // the sentence from `showLoadError`, which paints it red, to the success
    // arm, which painted every explanation yellow. A backend that never
    // answered is not a caveat.
    const deadBackend = await loadWith({
        error: 'Unable to connect to lab-es. Please check the connection.',
        error_type: 'elasticsearch_connection',
        panels: [{ ...PANEL, buckets: [], error: 'Unable to connect.' }],
    });
    check('a backend that did not answer is a red banner', () => {
        const box = deadBackend.document.getElementById('dashboardMessage');
        assert(box.classList.contains('alert-danger'),
               `the banner was "${box.className}"`);
    });

    // And the two that are ANSWERS keep the caution tone they have always
    // had: the scope really does reach none of these indices, and the filter
    // really is a typo.
    const outOfScope = await loadWith({
        error: 'No accessible indices for dashboard data.',
        error_type: 'no_accessible_containers',
        total_hits: 0, panels: [],
    });
    check('a scope that reaches nothing stays a caution', () => {
        const box = outOfScope.document.getElementById('dashboardMessage');
        assert(box.classList.contains('alert-warning'),
               `the banner was "${box.className}"`);
    });

    // A panel that could not be ANSWERED, as opposed to one that was answered
    // with nothing. 'No data in this window' is a claim about the data; a
    // Loki terms over a field that is not a label, or an Elasticsearch
    // group-by on a field that index maps as text, has no such answer. The
    // reason used to sit only in the page-level alert, which names the source
    // and not the panel, while the card in the middle of the screen said the
    // window was quiet.
    const unanswerable = await loadWith({
        total_hits: 0,
        warnings: ["'host' is not a Loki label on these streams"],
        panels: [{ ...PANEL, buckets: [], partial: true,
                   warnings: ["'host' is not a Loki label on these streams"] }],
    });
    check('an unanswerable panel prints its reason, not the empty literal', () => {
        const text = unanswerable.document
            .querySelector('.panel-empty small').textContent;
        assert(/not a Loki label/.test(text), `the card said "${text}"`);
        assert(!/No data in this window/.test(text), `the card said "${text}"`);
    });
    check('an unanswerable panel stops spinning', () =>
        assert(spinning(unanswerable) === 0,
               `${spinning(unanswerable)} spinner(s) left`));

    // And says it ONCE. The server marks the panel `partial` as well as
    // sending the reason, so the header read "Incomplete: 'host' is not a
    // Loki label on these streams" two lines above the same sentence where
    // the chart would be. The caveat earns its place beside numbers — a
    // service list short by one store — and there are none here.
    check('an unanswerable panel says its reason once, not twice', () => {
        const slot = unanswerable.document.querySelector('[data-panel-id="p1"]');
        const hint = slot.querySelector('.panel-hint').textContent;
        const body = slot.querySelector('.panel-empty small').textContent;
        assert(/not a Loki label/.test(body), `the card said "${body}"`);
        assert(!/not a Loki label/.test(hint) && !/Incomplete/.test(hint),
               `the header said "${hint}" over a card already saying it`);
    });

    // A series of zeroes is not something to draw either: renderPanel prints
    // the reason in the body for it too, so the header must not repeat it
    // there.
    const flatline = await loadWith({
        total_hits: 0,
        panels: [{ ...PANEL, type: 'timeseries', partial: true,
                   warnings: ['one shipper did not answer'],
                   buckets: [{ key: '10:00', count: 0 },
                             { key: '11:00', count: 0 }] }],
    });
    check('an all-zero series says its reason once too', () => {
        const slot = flatline.document.querySelector('[data-panel-id="p1"]');
        const hint = slot.querySelector('.panel-hint').textContent;
        const body = slot.querySelector('.panel-empty small').textContent;
        assert(/one shipper did not answer/.test(body),
               `the card said "${body}"`);
        assert(!/Incomplete/.test(hint), `the header said "${hint}"`);
    });

    // And the case that must NOT change: a window that really is quiet still
    // says so, because a panel with no reason has nothing better to print.
    const quiet = await loadWith({
        total_hits: 0,
        panels: [{ ...PANEL, buckets: [] }],
    });
    check('a genuinely quiet window still says no data', () => {
        const text = quiet.document.querySelector('.panel-empty small').textContent;
        assert(/No data in this window/.test(text), `the card said "${text}"`);
    });

    // A count the server did not send is a count that did not run. Zero is
    // the loudest possible version of that lie: "no errors".
    const outage = await loadWith({
        error: 'Unable to connect to lab-es. Please check the connection.',
        error_type: 'elasticsearch_connection',
        panels: [{ ...PANEL, buckets: [],
                   error: 'Unable to connect to lab-es.' }],
    });
    check('a count that did not run is an em dash, not zero', () => {
        const cards = ['totalHits', 'errorCount', 'warnCount', 'infoCount'];
        cards.forEach(id => {
            const text = outage.document.getElementById(id).textContent;
            assert(text === '—', `${id} read "${text}"`);
        });
        const rate = outage.document.getElementById('errorRate').textContent;
        assert(rate === '—', `errorRate read "${rate}"`);
    });
    check('a count of zero still reads as zero', () => {
        // `empty` above was loaded with total_hits: 0 explicitly — a window
        // that really held nothing. Zero is the answer there and must survive.
        const real = empty.document.getElementById('totalHits').textContent;
        assert(real === '0', `totalHits read "${real}" for a real zero`);
    });

    // A partial answer: panels drawn, with a note about what could not be
    // counted. The note reached the browser and stopped there.
    const noted = await loadWith({
        total_hits: 5,
        warnings: ["'host' is not a Loki label on these streams"],
        panels: [{ ...PANEL, buckets: [{ key: 'ERROR', count: 5 }] }],
    });
    check('a partial answer shows its warnings beside the panels', () => {
        const text = noted.document.getElementById('dashboardMessage').textContent;
        assert(/not a Loki label/.test(text), `the page said "${text}"`);
        assert(noted.document.querySelectorAll('.panel-slot').length === 1,
               'the panels that did answer were thrown away');
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

    // A drill-down puts chart values into the Logs query. They are bucket
    // keys — whatever a log writer put in the document — and were written
    // between quotes with nothing escaped, or with no quotes at all.
    {
        const w = makeDashboard(jsonResponse({}));
        const dashboard = new w.AsyncDashboard('d1');
        dashboard.lastData = { effective_query: 'service:payments' };
        const opened = [];
        w.open = (url) => opened.push(new URL(url, 'http://localhost')
                                         .searchParams.get('query'));
        dashboard.openLogs({ level: 'x OR service:hr-salaries' });
        dashboard.openLogs({ service: 'x" OR service:"hr-salaries' });
        dashboard.openLogs(dashboard.fieldFilter('host', 'h1" OR service:"hr'));
        dashboard.openLogs({ level: 'ERROR' });
        check('a chart value is one value in the query it opens', () => {
            assert(opened[0] === '(service:payments) AND level:"x OR service:hr-salaries"',
                   opened[0]);
            assert(opened[1] === '(service:payments) AND service:"x\\" OR service:\\"hr-salaries"',
                   opened[1]);
            assert(opened[2] === '(service:payments) AND host:"h1\\" OR service:\\"hr"',
                   opened[2]);
        });
        check('an ordinary level is written as it always was', () =>
            assert(opened[3] === '(service:payments) AND level:ERROR', opened[3]));
    }

    // A stat card must open the records it counted.
    //
    // The server sums ERROR and FATAL into the error card's number and WARN
    // and WARNING into the warn card's, and the click asked for `level:ERROR`
    // and `level:WARN`. Against the lab the error card read 3,093 and opened
    // 2,772: the 321 FATAL records it had counted could not be reached from
    // the number counting them. The grouping comes down with the counts now.
    {
        const w = makeDashboard(jsonResponse({}));
        const dashboard = new w.AsyncDashboard('board-7');
        const cards = ['cardTotal', 'cardError', 'cardWarn', 'cardInfo'];
        cards.forEach(id => {
            const el = w.document.createElement('div');
            el.id = id;
            w.document.body.appendChild(el);
        });
        dashboard.lastData = {
            effective_query: 'env:prod',
            level_queries: { error: '(level:ERROR OR level:FATAL)',
                             warn: '(level:WARN OR level:WARNING)',
                             info: '(level:INFO)' },
        };
        const opened = [];
        w.open = (url) => opened.push(new URL(url, 'http://localhost')
                                         .searchParams.get('query'));
        dashboard.setupStatCards();
        cards.forEach(id => w.document.getElementById(id).click());

        check('the error card opens every severity it counted', () =>
            assert(opened[1] === '(env:prod) AND (level:ERROR OR level:FATAL)',
                   opened[1]));
        check('and so does the warn card', () =>
            assert(opened[2] === '(env:prod) AND (level:WARN OR level:WARNING)',
                   opened[2]));
        check('the info card is unchanged in meaning', () =>
            assert(opened[3] === '(env:prod) AND (level:INFO)', opened[3]));
        check('the total card still filters by nothing', () =>
            assert(opened[0] === '(env:prod)', opened[0]));
    }

    // A card clicked before the first response has landed.
    {
        const w = makeDashboard(jsonResponse({}));
        const dashboard = new w.AsyncDashboard('board-7');
        check('a card clicked before any data still asks for the group', () =>
            assert(dashboard.levelQuery('error') === '(level:ERROR OR level:FATAL)',
                   dashboard.levelQuery('error')));
    }

    // A drill-down must be answered inside the dashboard's own containers.
    // The query went across and the dashboard did not, and /api/search with
    // no dashboard searches every container the ROLE allows — so clicking a
    // stat card on a dashboard over `app-logs-*` opened more records than
    // the card counted. Measured against the lab: 30,576 on the dashboard,
    // 91,407 on the drill-down, over five indices instead of one.
    {
        const w = makeDashboard(jsonResponse({}));
        const dashboard = new w.AsyncDashboard('board-7');
        dashboard.lastData = { effective_query: 'env:prod' };
        const opened = [];
        w.open = (url) => opened.push(new URL(url, 'http://localhost'));
        dashboard.openLogs({ level: 'ERROR' });
        const bucketWindow = {
            start: new Date('2026-09-01T10:00:00Z'),
            end: new Date('2026-09-01T11:00:00Z'),
        };
        dashboard.openLogs({ ...bucketWindow, service: 'api' });

        check('a drill-down names the dashboard it came from', () =>
            assert(opened[0].searchParams.get('dashboard') === 'board-7',
                   `it sent ${opened[0].search}`));
        check('and so does one from a single time bucket', () =>
            assert(opened[1].searchParams.get('dashboard') === 'board-7',
                   `it sent ${opened[1].search}`));
        check('the window still travels with it', () =>
            assert(opened[0].searchParams.get('time_range') === '1h'
                   && opened[1].searchParams.get('start'),
                   `it sent ${opened[0].search} / ${opened[1].search}`));
    }

    // A change made while a load is running used to be dropped: the select
    // and the address bar moved, the request never went out, and the page
    // went on showing the previous window's numbers under the new label.
    {
        let release;
        const held = new Promise(resolve => { release = resolve; });
        const requests = [];
        const w = makeDashboard(async (url) => {
            requests.push(url);
            if (requests.length === 1) await held;
            const range = new URL(url, 'http://localhost')
                .searchParams.get('time_range');
            return {
                ok: true, status: 200,
                json: async () => ({
                    total_hits: range === '24h' ? 24 : 1,
                    time_range: range, panels: [],
                }),
            };
        });
        w.document.getElementById('timeRange').innerHTML =
            '<option value="1h">1h</option><option value="24h">24h</option>';
        const dashboard = new w.AsyncDashboard('d1');
        // The first load is in flight and held. Change the range, the way the
        // handler does.
        const select = w.document.getElementById('timeRange');
        select.value = '24h';
        dashboard.syncUrl();
        dashboard.load();
        release();
        await settle(dashboard);

        check('a change made during a load is not dropped', () =>
            assert(requests.length === 2,
                   `${requests.length} request(s): ${requests.join(', ')}`));
        check('and the numbers on screen are the ones that were asked for', () =>
            assert(dashboard.lastData && dashboard.lastData.time_range === '24h',
                   `the page is showing ${dashboard.lastData
                       && dashboard.lastData.time_range}`));
        check('the control, the address bar and the data agree', () => {
            assert(select.value === '24h', `the select says ${select.value}`);
            assert(/time_range=24h/.test(w.location.search),
                   `the url says ${w.location.search}`);
            assert(w.document.getElementById('totalHits').textContent
                       .includes('24'),
                   'the card still shows the first window\'s count');
        });
    }

    // A trace service list whose fan-out lost a backend is not a shorter
    // list: the services that store held are missing and the counts of the
    // ones it shared are short. The answer says `partial`; the panel drew
    // the rows and said nothing, so a store that did not reply read as a
    // service having gone quiet.
    const TRACE = { id: 't1', title: 'Services', type: 'trace_services',
                    width: 6, sort: 'spans', size: 5 };
    const partial = await loadWith({
        total_hits: 1,
        panels: [{ ...TRACE, partial: true,
                   warnings: ['jaeger did not answer the service list'],
                   rows: [{ name: 'api', span_count: 10, error_count: 1,
                            error_rate: 0.1 }] }],
    });
    check('a partial service list says so beside its rows', () => {
        const slot = partial.document.querySelector('[data-panel-id="t1"]');
        const hint = slot.querySelector('.panel-hint').textContent;
        assert(/jaeger did not answer/.test(hint), `the panel said "${hint}"`);
        assert(slot.querySelectorAll('tbody tr').length === 1,
               'the rows that did arrive were thrown away');
    });

    const partialEmpty = await loadWith({
        total_hits: 1,
        panels: [{ ...TRACE, partial: true,
                   warnings: ['tempo did not answer the service list'],
                   rows: [] }],
    });
    check('an empty partial list is not "no trace data in this window"', () => {
        const said = partialEmpty.document
            .querySelector('[data-panel-id="t1"] .panel-empty small').textContent;
        assert(/tempo did not answer/.test(said), `the panel said "${said}"`);
    });

    const whole = await loadWith({
        total_hits: 1,
        panels: [{ ...TRACE, rows: [{ name: 'api', span_count: 10,
                                      error_count: 0, error_rate: 0 }] }],
    });
    // This check used to pin the defect: it asserted the service list wore
    // 'Click a value to filter by it', which was the hint the client set for
    // everything that is not a timeseries. Nothing filters — a click here
    // opens the Traces page in a new tab.
    check('a whole service list says what its click does', () => {
        const hint = whole.document
            .querySelector('[data-panel-id="t1"] .panel-hint').textContent;
        assert(/Traces page/.test(hint) && !/filter by it/.test(hint),
               `the panel said "${hint}"`);
    });

    // The hint every panel type added after this one inherits. A terms
    // panel's click calls openLogs, which opens the Logs page in a new tab:
    // it does not narrow this board and never has.
    const hinted = await loadWith({
        total_hits: 12,
        panels: [{ ...PANEL, field: 'service',
                   buckets: [{ key: 'api', count: 12 }] }],
    });
    check('a top-values panel promises the Logs page, not a filter', () => {
        const hint = hinted.document
            .querySelector('[data-panel-id="p1"] .panel-hint').textContent;
        assert(/Logs page/.test(hint) && !/filter by it/.test(hint),
               `the panel said "${hint}"`);
    });

    // The third row of the table, and the only hint the old ternary got
    // right — which is how it went unpinned: a change making it untrue again
    // passed every check here. It is the hint on the first panel of the
    // demo's own board. A timeseries click calls openLogs too.
    const overTime = await loadWith({
        total_hits: 12,
        panels: [{ ...PANEL, type: 'timeseries',
                   buckets: [{ key: '10:00', count: 12 }] }],
    });
    check('a volume panel says its segments open the Logs page', () => {
        const hint = overTime.document
            .querySelector('[data-panel-id="p1"] .panel-hint').textContent;
        assert(/Logs page/.test(hint) && !/filter by it/.test(hint),
               `the panel said "${hint}"`);
    });

    // The half that decides what the next six panel types inherit: a type
    // the table does not name makes no promise at all, rather than falling
    // through to the promise this whole check exists to remove.
    const novel = await loadWith({
        total_hits: 3,
        panels: [{ id: 'n1', title: 'Monitors', type: 'monitor_grid', width: 6,
                   buckets: [{ key: 'checkout', count: 3 }] }],
    });
    check('a panel type with no described click says nothing', () => {
        const hint = novel.document
            .querySelector('[data-panel-id="n1"] .panel-hint').textContent;
        assert(hint === '', `the panel said "${hint}"`);
    });

    // "A type the table does not name" has to mean every type it does not
    // name. A plain object literal inherits Object.prototype, so
    // PANEL_HINTS['constructor'] is a FUNCTION and the hint would have read
    // "function Object() { [native code] }" in the card header — the lookup
    // every panel type written after this one goes through.
    const inherited = await loadWith({
        total_hits: 3,
        panels: [{ id: 'n2', title: 'Built ins', type: 'constructor', width: 6,
                   buckets: [{ key: 'checkout', count: 3 }] }],
    });
    check('a panel type named after a built-in still says nothing', () => {
        const hint = inherited.document
            .querySelector('[data-panel-id="n2"] .panel-hint').textContent;
        assert(hint === '', `the panel said "${hint}"`);
    });

    // And the warning still outranks the hint, whatever the type.
    const novelPartial = await loadWith({
        total_hits: 3,
        panels: [{ id: 'n1', title: 'Monitors', type: 'monitor_grid', width: 6,
                   partial: true, warnings: ['one check did not answer'],
                   buckets: [{ key: 'checkout', count: 3 }] }],
    });
    check('an incomplete panel of an unknown type still says so', () => {
        const hint = novelPartial.document
            .querySelector('[data-panel-id="n1"] .panel-hint').textContent;
        assert(/one check did not answer/.test(hint), `the panel said "${hint}"`);
    });

    // The comparison cards, against a baseline that only partly answered.
    // Its counts are a floor and every percentage is measured against them;
    // the note said "Compared against the preceding window" and nothing else,
    // because the payload carries the CURRENT window's warnings only.
    const PREVIOUS = {
        total_hits: 60, error_count: 4, warn_count: 8, info_count: 40,
        error_rate: 4 / 60, window: { start: '2026-09-10T09:00:00Z',
                                      end: '2026-09-11T09:00:00Z' },
        change: { total_hits: 0.5, error_count: 1, warn_count: 0.5,
                  info_count: 1 },
    };
    const wholeBaseline = await loadWith({
        total_hits: 90, panels: [], previous_period: { ...PREVIOUS },
    });
    check('a baseline that answered in full is compared without a caveat', () => {
        const note = wholeBaseline.document
            .getElementById('baselineNote').textContent;
        assert(/preceding window/.test(note) && !/lower bound/.test(note),
               `the note said "${note}"`);
    });

    const shortBaseline = await loadWith({
        total_hits: 90, panels: [],
        previous_period: { ...PREVIOUS, partial: true,
                           warnings: ['5 of 9 shards failed: Fielddata is '
                                      + 'disabled on [level]'] },
    });
    check('a baseline that answered in part says the change is a floor', () => {
        const note = shortBaseline.document
            .getElementById('baselineNote').textContent;
        assert(/lower bound/.test(note) && /shards failed/.test(note),
               `the note said "${note}"`);
    });
    check('and the reason it gives is text', () => {
        const planted = shortBaseline.document
            .getElementById('baselineNote').innerHTML;
        assert(!/<img/.test(planted), planted);
    });

    const planted = await loadWith({
        total_hits: 90, panels: [],
        previous_period: { ...PREVIOUS, partial: true,
                           warnings: ['<img src=x id=planted6>'] },
    });
    check('a baseline warning cannot bring markup with it', () =>
        assert(!planted.document.getElementById('planted6'),
               planted.document.getElementById('baselineNote').innerHTML));

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

    // A theme switch re-resolves every token in the stylesheet and nothing
    // on a canvas: the charts stayed in the colours they were first drawn
    // in until the page was reloaded. They are drawn again from the answer
    // already on the page, with the palette as it is now.
    const themed = await loadWith({
        total_hits: 12,
        panels: [{ ...PANEL, buckets: [{ key: 'ERROR', count: 12 }] }],
    });
    const root = themed.document.documentElement;
    root.style.setProperty('--text-primary', '#010101');
    root.style.setProperty('--fill-red', '#0a0a0a');
    const before = themed.dashboard.charts.p1;
    const fetched = { count: 0 };
    global.fetch = themed.fetch = async () => {
        fetched.count += 1;
        return { ok: true, status: 200, json: async () => ({ panels: [] }) };
    };
    themed.document.dispatchEvent(new themed.CustomEvent(
        'wdash:theme', { detail: { theme: 'light' } }));
    await settle(themed.dashboard);
    const after = themed.dashboard.charts.p1;
    check('a theme switch draws the charts again, in the new colours', () => {
        assert(after && after !== before, 'the chart was not rebuilt');
        assert(themed.Chart.defaults.color === '#010101',
               `Chart.defaults.color is ${themed.Chart.defaults.color}`);
        const colours = JSON.stringify(after.config.data.datasets);
        assert(colours.includes('#0a0a0a'),
               `the bars kept their old colour: ${colours}`);
    });
    check('and without asking the backend for a colour change', () =>
        assert(fetched.count === 0, `it fetched ${fetched.count} time(s)`));

    // ---- monitors on the board ------------------------------------------
    //
    // The panel that tells a quiet night from a dead log shipper. Every
    // failure mode of it has to look like a failure: an empty grid, a
    // percentage over a check that never ran, or a certificate verdict
    // nobody measured would each read as "all clear".

    const MONITOR = { id: 'm1', title: 'Checks', type: 'monitors', width: 6 };

    const grid = await loadWith({
        panels: [{
            ...MONITOR, view: 'status',
            counts: { up: 1, down: 1, unknown: 0 },
            rows: [
                { id: 'down-1', name: 'Lab endpoint (down)', status: 'down',
                  duration_ms: 1.6, checked_at: '2026-09-12T11:25:42Z',
                  error: 'received status code 500 expecting [200]',
                  location: 'lab:8080' },
                { id: 'up-1', name: 'Lab endpoint (up)', status: 'up',
                  duration_ms: 1.6, checked_at: '2026-09-12T11:25:42Z',
                  error: '', location: 'lab:8080' },
            ],
        }],
    });
    check('a monitor grid draws one cell per check', () => {
        const cells = grid.document.querySelectorAll('[data-monitor]');
        assert(cells.length === 2, `${cells.length} cell(s) drawn`);
    });
    check('a monitor grid stops spinning', () =>
        assert(spinning(grid) === 0, `${spinning(grid)} spinner(s) left`));
    check('a down cell carries its status and its reason', () => {
        const cell = grid.document.querySelector('[data-monitor="down-1"]');
        assert(/status code 500/.test(cell.textContent),
               `the reason is missing: "${cell.textContent}"`);
        assert(cell.querySelector('.monitor-status.down'),
               'the down chip is missing');
    });
    check('a status grid says it is showing status', () => {
        const text = grid.document.querySelector('.chart-container').textContent;
        assert(/Status at the last check/.test(text), `caption was "${text}"`);
        assert(!/Availability/.test(text), 'it also claimed availability');
    });
    check('the monitor hint does not promise a filter', () => {
        const hint = grid.document.querySelector('.panel-hint').textContent;
        assert(!/filter by it/i.test(hint), `the hint reads "${hint}"`);
        assert(/Monitors page/.test(hint), `the hint reads "${hint}"`);
    });

    const uptime = await loadWith({
        panels: [{
            ...MONITOR, view: 'availability',
            counts: { up: 1, down: 0, unknown: 1 },
            rows: [
                { id: 'a1', name: 'Lab shop journey', status: 'up',
                  checked_at: '2026-09-12T11:25:56Z', error: '',
                  checks: 945, down: 11, availability: 98.84 },
                { id: 'a2', name: 'Never ran', status: 'unknown',
                  checked_at: null, error: 'no agent has reported',
                  checks: 0, down: 0, availability: null },
            ],
        }],
    });
    check('an availability grid says it is showing availability', () => {
        const text = uptime.document.querySelector('.chart-container').textContent;
        assert(/Availability over the window/.test(text),
               `caption was "${text}"`);
    });
    check('a percentage never travels without its check count', () => {
        const cell = uptime.document.querySelector('[data-monitor="a1"]');
        assert(/98\.84%/.test(cell.textContent), cell.textContent);
        assert(/945/.test(cell.textContent),
               `the check count is missing: "${cell.textContent}"`);
    });
    check('a check that never ran is not a hundred percent', () => {
        const cell = uptime.document.querySelector('[data-monitor="a2"]');
        assert(/no check ran/.test(cell.textContent), cell.textContent);
        assert(!/%/.test(cell.textContent),
               `it printed a percentage: "${cell.textContent}"`);
    });

    // `quiet` is taken by the log panel's own empty-window check above, and
    // the two are different claims about different sources.
    const noMonitor = await loadWith({
        panels: [{ ...MONITOR, view: 'status', counts: {}, rows: [] }],
    });
    check('a window with no monitor in it says so rather than drawing calm', () => {
        const text = noMonitor.document.querySelector('.panel-empty small').textContent;
        assert(/No monitor has reported/.test(text), `message was "${text}"`);
    });

    const short = await loadWith({
        panels: [{ ...MONITOR, view: 'status', counts: {}, rows: [],
                   partial: true, warnings: ['region-b: connection refused'] }],
    });
    check('a listing that came back short names the source that did not answer', () => {
        const text = short.document.querySelector('.panel-empty small').textContent;
        assert(/region-b/.test(text), `message was "${text}"`);
    });

    const hostile = await loadWith({
        panels: [{
            ...MONITOR, view: 'status', counts: { down: 1 },
            rows: [{ id: 'x', name: '<img src=x onerror=alert(1)>',
                     status: 'down', duration_ms: 1, checked_at: null,
                     error: '<script>bad()</script>', location: '' }],
        }],
    });
    check('a monitor name is text, not markup', () => {
        assert(!hostile.document.querySelector('#panelGrid img'),
               'a name planted an img tag');
        assert(!hostile.document.querySelector('#panelGrid script'),
               'an error message planted a script tag');
    });

    const certificates = await loadWith({
        panels: [{
            id: 'c1', title: 'Certificates', type: 'monitor_certificates',
            width: 6, warning_days: 30, critical_days: 7,
            rows: [
                { id: 'gone', name: 'TLS endpoint (expiring)',
                  common_name: 'expiring.lab.local', location: 'lab:8443',
                  days_remaining: -25, expired: true, state: 'expired',
                  verified: null, tls_mode: '' },
                { id: 'soon', name: 'Payments', common_name: 'pay.lab.local',
                  location: 'lab:9443', days_remaining: 3, expired: false,
                  state: 'critical', verified: false, tls_mode: '' },
                { id: 'fine', name: 'TLS endpoint (valid)',
                  common_name: 'healthy.lab.local', location: 'lab:8444',
                  days_remaining: 328, expired: false, state: 'ok',
                  verified: null, tls_mode: '' },
            ],
        }],
    });
    check('an expired certificate says expired, not a negative number', () => {
        const row = certificates.document.querySelector('[data-monitor="gone"]');
        assert(/expired/i.test(row.textContent), row.textContent);
        assert(!/-25/.test(row.textContent),
               `it printed the raw day count: "${row.textContent}"`);
    });
    check('the band comes from the server, not from the day count', () => {
        const chip = certificates.document
            .querySelector('[data-monitor="soon"] .expiry-chip');
        assert(chip.classList.contains('critical'),
               `chip classes were "${chip.className}"`);
    });
    check('a certificate nobody measured a verdict for carries no verdict', () => {
        const row = certificates.document.querySelector('[data-monitor="fine"]');
        assert(!/not verified/i.test(row.textContent), row.textContent);
    });
    check('a handshake that really failed does say so', () => {
        const row = certificates.document.querySelector('[data-monitor="soon"]');
        assert(/not verified/i.test(row.textContent), row.textContent);
    });
    check('the thresholds the bands came from are printed under them', () => {
        const text = certificates.document
            .querySelector('.chart-container').textContent;
        assert(/below 30 days/.test(text) && /below 7/.test(text),
               `the footnote read "${text}"`);
    });

    // A list that is missing whichever region did not answer must not read
    // as the whole estate. The certificate expiring tomorrow may be exactly
    // the one that is absent.
    const shortList = await loadWith({
        panels: [{
            id: 'c1', title: 'Certificates', type: 'monitor_certificates',
            width: 6, warning_days: 30, critical_days: 7,
            partial: true, warnings: ['region-b: connection refused'],
            rows: [
                { id: 'fine', name: 'TLS endpoint (valid)',
                  common_name: 'healthy.lab.local', location: 'lab:8444',
                  days_remaining: 328, expired: false, state: 'ok',
                  verified: null, tls_mode: '' },
            ],
        }],
    });
    check('a certificate list that came back short says which source is missing', () => {
        const text = shortList.document
            .querySelector('.chart-container').textContent;
        assert(/region-b/.test(text), `the card said "${text}"`);
        assert(/may be missing/.test(text), `the card said "${text}"`);
    });

    const noneAnswered = await loadWith({
        panels: [{ id: 'c1', title: 'Certificates',
                   type: 'monitor_certificates', width: 6, rows: [],
                   partial: true,
                   warnings: ['region-b: connection refused'] }],
    });
    check('no source answering is not "none of these checks use TLS"', () => {
        const text = noneAnswered.document
            .querySelector('.panel-empty small').textContent;
        assert(/region-b/.test(text), `message was "${text}"`);
        assert(!/used TLS/.test(text),
               `it made a claim about the endpoints: "${text}"`);
    });

    const noTls = await loadWith({
        panels: [{ id: 'c1', title: 'Certificates',
                   type: 'monitor_certificates', width: 6, rows: [] }],
    });
    check('no certificate in the window is not an empty card', () => {
        const text = noTls.document.querySelector('.panel-empty small').textContent;
        assert(/None of the checks in this window used TLS/.test(text),
               `message was "${text}"`);
    });

    const denied = await loadWith({
        panels: [{ ...MONITOR, error: 'Monitors need the monitors:read permission.' }],
    });
    check('a panel refused for want of a permission says which', () => {
        const text = denied.document.querySelector('.panel-empty small').textContent;
        assert(/monitors:read/.test(text), `message was "${text}"`);
    });

    // The board that is half answerable: the log source is down, the monitor
    // source is not. The panels draw, and the four tiles above them are the
    // LOG source's — nobody counted them. Printed as zeros they read "0
    // records, 0 errors, 0.00%" over a healthy green grid, which is the
    // quiet night this whole panel exists to disprove.
    //
    // The body says so by OMITTING the counts — there is no flag to read, and
    // `updateStats` prints an em dash for a count that is not there. The
    // check above ('a count that did not run is an em dash, not zero') pins
    // that rule over a board of log panels; this one pins it in the case that
    // made it urgent, with something healthy drawn underneath.
    const halfDead = await loadWith({
        error: 'Unable to connect to elasticsearch. Please check the connection.',
        error_type: 'elasticsearch_connection',
        previous_period: null, status: null,
        panels: [{
            ...MONITOR, view: 'status', counts: { up: 1, down: 0, unknown: 0 },
            rows: [{ id: 'up-1', name: 'Checkout', status: 'up',
                     duration_ms: 1.6, checked_at: '2026-09-12T11:25:42Z',
                     error: '', location: 'lab:8080' }],
        }],
    });
    check('counts nobody could make are not printed as zero', () => {
        const tiles = ['totalHits', 'errorCount', 'warnCount', 'infoCount']
            .map(id => halfDead.document.getElementById(id).textContent);
        assert(tiles.every(text => text === '—'),
               `the tiles read ${JSON.stringify(tiles)}`);
        assert(halfDead.document.getElementById('errorRate').textContent === '—',
               'the error rate was reported as 0.00%');
    });
    check('and the monitor grid is still drawn beside them', () => {
        assert(halfDead.document.querySelector('[data-monitor="up-1"]'),
               'the panel that survives the outage was not drawn');
        const box = halfDead.document.getElementById('dashboardMessage');
        assert(/Unable to connect/.test(box.textContent),
               `the reason was not said: "${box.textContent}"`);
    });

    // Real counts still print. A tile that says "-" whatever the answer is
    // would pass the check above and tell nobody anything.
    const counted = await loadWith({
        total_hits: 1234, error_count: 12, warn_count: 3, info_count: 1219,
        error_rate: 0.0097, panels: [],
    });
    check('a board that was counted still prints its counts', () => {
        assert(counted.document.getElementById('totalHits').textContent === '1,234',
               counted.document.getElementById('totalHits').textContent);
        assert(counted.document.getElementById('errorRate').textContent === '0.97%',
               counted.document.getElementById('errorRate').textContent);
    });

    // ------------------------------------------------------ records table
    //
    // The footer is a claim about the BACKEND, not about the rows. Measured
    // against the lab at 24h: Elasticsearch answers 10 of 5,015 and
    // VictoriaLogs 10 of 681 with counted=true, while Loki returns up to its
    // limit and stops — 10 records, total 10, counted=false. "10 of 10" from
    // Loki is a total nobody measured, and it reads as "that is all there
    // was".
    const RECORD = {
        timestamp: '2026-09-11T10:00:00.000Z', severity: 'ERROR',
        severity_text: 'ERROR', service: 'payments', body: 'boom',
    };
    const counting = await loadWith({
        panels: [{ id: 'r1', type: 'records', title: 'Recent', width: 6,
                   rows: [RECORD, { ...RECORD, body: 'again' }],
                   total: 5015, counted: true }],
    });
    check('a counted records panel prints the match count', () => {
        const text = counting.document.querySelector(
            '[data-panel-id="r1"] .chart-container').textContent;
        assert(/Showing 2 of 5,015/.test(text), `the caption read "${text}"`);
    });
    check('a records panel draws a row per record', () => {
        const rows = counting.document.querySelectorAll(
            '[data-panel-id="r1"] tbody tr');
        assert(rows.length === 2, `${rows.length} rows drawn`);
        assert(/payments/.test(rows[0].textContent), rows[0].textContent);
    });
    check('a records panel stops spinning', () =>
        assert(spinning(counting) === 0, `${spinning(counting)} spinner(s) left`));

    const uncounted = await loadWith({
        panels: [{ id: 'r1', type: 'records', title: 'Recent', width: 6,
                   rows: [RECORD], total: 1, counted: false,
                   warnings: ['Loki reports no match count'] }],
    });
    check('a source that reports no match count never says "1 of 1"', () => {
        const text = uncounted.document.querySelector(
            '[data-panel-id="r1"] .chart-container').textContent;
        assert(!/of 1\b/.test(text), `the caption read "${text}"`);
        assert(/does not report a match count/.test(text),
               `the caption read "${text}"`);
    });

    // A record body is whatever a log writer put in the document.
    const nasty = await loadWith({
        panels: [{ id: 'r1', type: 'records', title: 'Recent', width: 6,
                   rows: [{ ...RECORD, body: '<img src=x onerror=alert(1)>',
                            service: '<b>x</b>' }],
                   total: 1, counted: true }],
    });
    check('a record is text in the table, not markup', () => {
        const cell = nasty.document.querySelector('[data-panel-id="r1"] tbody tr');
        assert(!cell.querySelector('img') && !cell.querySelector('b'),
               'a record body was rendered as markup');
        assert(/onerror=alert\(1\)/.test(cell.textContent), cell.textContent);
    });

    const unread = await loadWith({
        panels: [{ id: 'r1', type: 'records', title: 'Recent', width: 6,
                   rows: [], total: 0, counted: true,
                   partial: true, warnings: ['lab-loki did not answer'] }],
    });
    check('a records panel that could not be read does not say the window was quiet', () => {
        const text = unread.document.querySelector(
            '[data-panel-id="r1"] .panel-empty small').textContent;
        assert(/did not answer/.test(text), `it said "${text}"`);
    });

    // ------------------------------------------------------- trace list
    //
    // The click carries the window being looked at and the store that
    // answered. Without the range the detail page opens at its own default
    // and reports a trace from last Tuesday as missing; without the source a
    // Jaeger trace is looked for in whichever store is first.
    const traceBoard = await loadWith({
        time_range: '24h',
        panels: [{ id: 't1', type: 'trace_list', title: 'Slowest', width: 6,
                   service: 'payments', view: 'slowest',
                   rows: [{ trace_id: 'abc123def456789', service: 'payments',
                            name: 'GET /pay', start: '2026-09-11T10:00:00.000Z',
                            duration_us: 9000, has_error: true,
                            source: 'lab-jaeger' }] }],
    });
    check('a trace list draws its rows', () => {
        const rows = traceBoard.document.querySelectorAll(
            '[data-panel-id="t1"] tbody tr');
        assert(rows.length === 1, `${rows.length} rows drawn`);
        assert(/9\.0 ms/.test(rows[0].textContent), rows[0].textContent);
    });
    check('a trace row opens the waterfall in the window being looked at', () => {
        const opened = [];
        traceBoard.open = (url) => opened.push(new URL(url, 'http://localhost'));
        traceBoard.document.querySelector('[data-trace]').click();
        assert(opened.length === 1, 'the row opened nothing');
        assert(opened[0].pathname === '/traces/abc123def456789',
               opened[0].pathname);
        assert(opened[0].searchParams.get('time_range') === '24h',
               `it sent ${opened[0].search}`);
        assert(opened[0].searchParams.get('source') === 'lab-jaeger',
               `it sent ${opened[0].search}`);
    });
    check('a trace list stops spinning', () =>
        assert(spinning(traceBoard) === 0, `${spinning(traceBoard)} spinner(s) left`));

    const noTraces = await loadWith({
        panels: [{ id: 't1', type: 'trace_list', title: 'Slowest', width: 6,
                   service: 'payments', view: 'slowest', rows: [] }],
    });
    check('an empty trace list names the service it asked about', () => {
        const text = noTraces.document.querySelector(
            '[data-panel-id="t1"] .panel-empty small').textContent;
        assert(/payments/.test(text), `it said "${text}"`);
    });

    // Every panel type ships with a caption, and neither of these two is a
    // click promise the panel does not keep: the records table exists so
    // that reading the records does NOT cost the board.
    check('the new panels carry a caption that is true of them', () => {
        const records = counting.document.querySelector(
            '[data-panel-id="r1"] .panel-hint').textContent;
        const traces = traceBoard.document.querySelector(
            '[data-panel-id="t1"] .panel-hint').textContent;
        assert(records && !/click/i.test(records), `records hint: "${records}"`);
        assert(/click/i.test(traces) && /waterfall/i.test(traces),
               `trace hint: "${traces}"`);
    });

    // One rule, two copies: the link a cell opens is built in JavaScript and
    // the route's converter is Python. MonitorLinkTest holds the same ids to
    // the same strings on the Python side.
    const LINKS = {
        '.': '~.',
        '..': '~..',
        '~': '~7E',
        'a~b': 'a~7Eb',
        'a/b': 'a%2Fb',
        "o'brien": 'o%27brien',
        'a(b)c': 'a%28b%29c',
        'a*b': 'a%2Ab',
        '!x': '%21x',
        'héllo': 'h%C3%A9llo',
        'plain-id_1.2': 'plain-id_1.2',
    };
    check('a monitor link is the same one segment the route builds', () => {
        const built = {};
        Object.keys(LINKS).forEach(id => {
            built[id] = grid.monitorUrl(id).replace('/monitors/', '');
        });
        assert(JSON.stringify(built) === JSON.stringify(LINKS),
               `the link builder produced ${JSON.stringify(built)}`);
    });

    console.log('');
    if (failures.length) {
        console.log(`${failures.length} dashboard check(s) failed\n`);
        process.exit(1);
    }
    console.log('all dashboard checks passed\n');
}

main().catch(e => { console.error(e); process.exit(1); });
