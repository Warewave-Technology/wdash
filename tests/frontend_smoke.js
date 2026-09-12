/**
 * Runtime smoke test for the browser bundle.
 *
 * The Python suite never loads the JavaScript, so a dead front end passes
 * every test. Three faults reached the working tree this way: a method called
 * in three places but never defined, an undefined variable in the record
 * detail, and a JSON highlighter that rewrote the text it was colouring.
 *
 * None of them are syntax errors — only running the code finds them. This
 * opens the log detail modal against a fake DOM and asserts what the user
 * would see.
 *
 * Run: npm test        (or: node tests/frontend_smoke.js)
 * Skipped by the Python suite when jsdom is not installed.
 */

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const ROOT = path.join(__dirname, '..');
const failures = [];

function check(name, fn) {
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

function assertEqual(actual, expected, message) {
    if (actual !== expected) {
        throw new Error(`${message}\n        expected: ${JSON.stringify(expected)}` +
                        `\n        actual:   ${JSON.stringify(actual)}`);
    }
}

// --- a DOM with the pieces logs.html provides ---------------------------

function makeWindow(fetchImpl) {
    const dom = new JSDOM(`<!doctype html><body>
        <form id="searchForm"><input id="query" name="query" value="*">
          <select id="sourceSelect" name="source">
            <option value="primary" selected>primary</option>
            <option value="archive">archive</option></select>
          <select id="timeRange"><option value="1h" selected>1h</option>
          <option value="custom">custom</option></select>
          <input id="startTime"><input id="endTime">
          <div id="customStartGroup"></div><div id="customEndGroup"></div>
        </form>
        <div id="resultsInfo"></div><div id="pagination"></div>
        <div id="errorDisplay" class="d-none"><div id="errorAlert">
          <div id="errorContent"></div></div></div>
        <div id="logEntries"></div><div id="emptyState"></div>
        <span id="totalIndicesBadge"></span>
        <span id="dashboardScopeBadge" class="d-none"></span>
        <div id="savedSearchList"></div>
        <div id="searchResults"></div>
        <div class="card d-none" id="sourceBreakdownCard">
          <div id="sourceBreakdownContent"></div>
        </div>
        <div id="fieldStatsContent"></div>
        <div class="modal fade" id="logModal">
          <h5 id="logModalTitle"></h5>
          <div class="modal-body" id="logModalBody"></div>
          <div id="contextControls"><button id="contextAllBtn"></button></div>
        </div></body>`, { runScripts: 'outside-only', url: 'http://localhost/logs' });

    const w = dom.window;
    global.window = w;
    global.document = w.document;
    w.bootstrap = {
        Modal: class { constructor() {} show() { this.shown = true; }
                       hide() {} static getInstance() { return null; } },
        Tooltip: class {}, Alert: class { close() {} },
    };
    w.navigator.clipboard = { writeText: () => Promise.resolve() };
    w.fetch = fetchImpl || (() => new Promise(() => {}));

    w.eval(fs.readFileSync(path.join(ROOT, 'static/js/wdash.min.js'), 'utf8') +
           '\n; window.__LogSearch = LogSearch; window.__WDash = WDash;');
    return w;
}

const RECORD = {
    ref: 'elasticsearch:infra-logs-000001:doc-1',
    timestamp: '2026-08-04T09:30:12.142Z',
    severity: 'WARN', severity_text: 'WARNING',
    service: 'payment-service', body: 'disk usage above threshold',
    resource: { host: 'node-3' }, attributes: { correlation_id: 'corr-9' },
};

const RAW_DOCUMENT = {
    _index: 'infra-logs-000001', _id: 'doc-1',
    _source: {
        '@timestamp': '2026-08-04T09:30:12.142Z', level: 'WARNING',
        message: 'disk usage above threshold', correlation_id: 'corr-9',
    },
};

console.log('front-end smoke');

// --- the detail views ask the source a record came from ------------------
//
// They asked the default source whatever the record's origin, and the id was
// cut at its first colon. And the context controls gained a listener on
// every opening: one click asked for the context of every record opened so
// far, and whichever answered last was shown under the current one.

check('the detail views name the record\'s source and keep its whole id', () => {
    const urls = [];
    const w = makeWindow(url => { urls.push(url); return new Promise(() => {}); });
    const search = Object.create(w.__LogSearch.prototype);
    search.showLogModal({ ...RECORD, ref: 'elasticsearch:app-logs-1:a:b:c',
                          source: 'secondary' });
    assert(urls.includes('/api/log/app-logs-1/a%3Ab%3Ac?source=secondary'),
           `the record was asked for as ${JSON.stringify(urls)}`);
    search._loadRawDocument('elasticsearch:app-logs-1:a:b:c');
    assert(urls.includes('/api/log/app-logs-1/a%3Ab%3Ac/raw?source=secondary'),
           `the raw document was asked for as ${JSON.stringify(urls)}`);
});

check('one click asks for the context of the record that is open, once', () => {
    const urls = [];
    const w = makeWindow(url => { urls.push(url); return new Promise(() => {}); });
    const search = Object.create(w.__LogSearch.prototype);
    search.showLogModal({ ...RECORD, ref: 'elasticsearch:first-1:doc-a',
                          source: 'primary' });
    search.showLogModal({ ...RECORD, ref: 'elasticsearch:second-1:doc-b',
                          source: 'secondary' });
    urls.length = 0;
    w.document.getElementById('contextAllBtn').click();
    const asked = urls.filter(u => u.includes('/context'));
    assertEqual(JSON.stringify(asked),
                JSON.stringify(['/api/log/second-1/doc-b/context?count=10&source=secondary']),
                'the context requests after one click');
});

// --- the detail modal opens at all --------------------------------------

check('the log detail modal renders', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.showLogModal(RECORD);          // threw on `queryKey` before
    const body = w.document.getElementById('logModalBody');
    assert(body.innerHTML.length > 0, 'the modal body was never populated');
    assert(body.querySelector('.field-table-container'), 'no field table');
});

check('the modal offers every tab, Raw included', () => {
    const w = makeWindow();
    Object.create(w.__LogSearch.prototype).showLogModal(RECORD);
    ['tabFields', 'tabMessage', 'tabRawJson', 'tabSource'].forEach(id =>
        assert(w.document.getElementById(id), `missing tab: ${id}`));
});

check('field filter icons are bound', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.showLogModal(RECORD);          // threw on `_bindFieldActions` before
    const icon = w.document.querySelector('#fieldsView [data-filter]');
    assert(icon, 'no filter icon rendered');
    assertEqual(icon.dataset.bound, 'true', 'the filter icon has no click handler');
});

check('clicking a field narrows the search instead of replacing it', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    let searched = false;
    search.performSearch = () => { searched = true; };
    w.document.getElementById('query').value = 'level:ERROR';

    search._applyFieldFilter('service:"payment-service"');
    assertEqual(w.document.getElementById('query').value,
                'level:ERROR AND service:"payment-service"',
                'clauses must accumulate with AND');
    assert(searched, 'the search was not re-run');
});

// --- a drill-down from a dashboard stays inside that dashboard ----------
//
// The click-through carries `dashboard=<id>`, which is what decides WHERE
// the query runs: /api/search with no dashboard searches every container the
// role allows, so a card on a dashboard over `app-logs-*` opened more records
// than it counted. The page has to keep the id and send it back on every
// search made from here, not only the first.

check('the Logs page keeps the dashboard a drill-down came from', () => {
    const w = makeWindow();
    w.history.replaceState(null, '', '/logs?query=level%3AERROR&dashboard=board-7');
    const search = Object.create(w.__LogSearch.prototype);
    search.performSearch = () => {};
    search._applyUrlParams();
    assertEqual(search.scopedDashboard, 'board-7',
                'the dashboard was read off the URL and thrown away');
});

check('and sends it back with the search', () => {
    const calls = [];
    const w = makeWindow((url) => { calls.push(url); return new Promise(() => {}); });
    const search = Object.create(w.__LogSearch.prototype);
    search.searchForm = w.document.getElementById('searchForm');
    search.scopedDashboard = 'board-7';
    ['showLoading', 'hideError', 'displayResults', 'updateIndexInfo',
     'renderSourceBreakdown', 'loadFieldStats'].forEach(name => {
        search[name] = () => {};
    });
    search.performSearch();
    assertEqual(calls.length, 1, `it made ${calls.length} request(s)`);
    assertEqual(new URL(calls[0], 'http://localhost').searchParams.get('dashboard'),
                'board-7', `it asked ${calls[0]}`);
});

check('an ordinary search still names no dashboard', () => {
    const calls = [];
    const w = makeWindow((url) => { calls.push(url); return new Promise(() => {}); });
    const search = Object.create(w.__LogSearch.prototype);
    search.searchForm = w.document.getElementById('searchForm');
    ['showLoading', 'hideError', 'displayResults', 'updateIndexInfo',
     'renderSourceBreakdown', 'loadFieldStats'].forEach(name => {
        search[name] = () => {};
    });
    search.performSearch();
    assert(!new URL(calls[0], 'http://localhost').searchParams.has('dashboard'),
           `it asked ${calls[0]}`);
});

check('a scoped page says which dashboard it is scoped to', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.updateIndexInfo({
        accessible_containers: ['app-logs-000001'],
        dashboard: { id: 'board-7', name: 'App board',
                     containers: ['app-logs-000001'] },
    });
    const badge = w.document.getElementById('dashboardScopeBadge');
    assert(!badge.classList.contains('d-none'), 'the badge stayed hidden');
    assert(/App board/.test(badge.textContent),
           `the badge said "${badge.textContent}"`);
});

// A dashboard may be pinned to a store of its own, and /api/search answers a
// drill-down from THAT store — while this page's picker sat on its first
// option and re-sent it with every later search, where the server quietly
// preferred the dashboard's. The control said "primary", the records came
// from "archive", and the per-record source badges disagreed with the picker
// above them.

check('a drill-down from a pinned dashboard names the store that answered', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.updateIndexInfo({
        accessible_containers: ['app-logs-000001'],
        dashboard: { id: 'board-7', name: 'App board', source: 'archive',
                     containers: ['app-logs-000001'] },
    });
    const badge = w.document.getElementById('dashboardScopeBadge');
    assert(/archive/.test(badge.textContent),
           `the badge said "${badge.textContent}"`);
});

check('and moves the picker to it, so the next search agrees', () => {
    const calls = [];
    const w = makeWindow((url) => { calls.push(url); return new Promise(() => {}); });
    const search = Object.create(w.__LogSearch.prototype);
    search.searchForm = w.document.getElementById('searchForm');
    search.scopedDashboard = 'board-7';
    ['showLoading', 'hideError', 'displayResults', 'renderSourceBreakdown',
     'loadFieldStats'].forEach(name => { search[name] = () => {}; });

    assertEqual(w.document.getElementById('sourceSelect').value, 'primary',
                'the picker did not start on its first option');
    search.updateIndexInfo({
        accessible_containers: ['app-logs-000001'],
        dashboard: { id: 'board-7', name: 'App board', source: 'archive',
                     containers: ['app-logs-000001'] },
    });
    assertEqual(w.document.getElementById('sourceSelect').value, 'archive',
                'the picker still showed a store the answer did not come from');

    search.performSearch();
    assertEqual(new URL(calls[0], 'http://localhost').searchParams.get('source'),
                'archive', `it asked ${calls[0]}`);
});

check('an unpinned drill-down leaves the picker alone', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.updateIndexInfo({
        accessible_containers: ['a'],
        dashboard: { id: 'board-7', name: 'App board', containers: ['a'] },
    });
    assertEqual(w.document.getElementById('sourceSelect').value, 'primary',
                'a dashboard naming no source moved the picker anyway');
});

check('and an unscoped one says nothing', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.updateIndexInfo({ accessible_containers: ['a', 'b'] });
    assert(w.document.getElementById('dashboardScopeBadge')
            .classList.contains('d-none'),
           'an ordinary search claimed to be scoped to a dashboard');
});

check('a bare * is replaced rather than kept as a clause', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.performSearch = () => {};
    w.document.getElementById('query').value = '*';
    search._applyFieldFilter('host:"node-3"');
    assertEqual(w.document.getElementById('query').value, 'host:"node-3"',
                '"*" is not a filter to preserve');
});

// --- the Raw tab --------------------------------------------------------

check('the Raw tab fetches only when opened, and only once', () => {
    const calls = [];
    const w = makeWindow((url) => {
        calls.push(url);
        if (url.endsWith('/raw')) {
            return Promise.resolve({ ok: true, status: 200,
                json: () => Promise.resolve({ found: true, backend: 'elasticsearch',
                                              document: RAW_DOCUMENT }) });
        }
        return new Promise(() => {});
    });
    const search = Object.create(w.__LogSearch.prototype);
    search.showLogModal(RECORD);

    assertEqual(calls.filter(u => u.endsWith('/raw')).length, 0,
                'the raw document was fetched before the tab was opened');

    w.document.getElementById('tabSource').dispatchEvent(new w.Event('click'));
    w.document.getElementById('tabSource').dispatchEvent(new w.Event('click'));
    assertEqual(calls.filter(u => u.endsWith('/raw')).length, 1,
                're-opening the tab must not re-fetch');
});

// --- what the server and the logs say is text ----------------------------
//
// Each of these went into the page as markup. The error box echoed the
// query a /logs?query= link carried; Elasticsearch's own numbers — a total,
// a `took`, a bucket count — came through as whatever the answer held; and
// `escapeHtml`, correct for text, was used inside quoted attributes, where
// it leaves the quotes alone.

check('an error and the index names in it are shown as text', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.showError('bad query <img src=x id=planted1>', 'no_accessible_containers',
                     { available_indices: ['app-<b id=planted2>x</b>'] });
    const box = w.document.getElementById('errorContent');
    assert(!w.document.getElementById('planted1')
           && !w.document.getElementById('planted2'), box.innerHTML);
    assert(box.textContent.includes('bad query <img src=x id=planted1>'),
           box.textContent);
});

// The logs page now names the source it could not reach — "Unable to connect
// to loki-down" — and then advised, in the same box, going to check
// Elasticsearch. /api/search returns error_type elasticsearch_connection for
// every backend, Loki and VictoriaLogs included.
check('a source that is down is not blamed on Elasticsearch', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.showError('Unable to connect to loki-down. Please check the connection.',
                     'elasticsearch_connection', { source: 'loki-down' });
    const text = w.document.getElementById('errorContent').textContent;
    assert(text.includes('Check if loki-down is running'),
           `the box advised: ${text}`);
    assert(!text.includes('Elasticsearch'),
           `a Loki user was sent to Elasticsearch: ${text}`);
});

check('a connection error with no source named still suggests something', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.showError('Unable to connect.', 'elasticsearch_connection', {});
    const text = w.document.getElementById('errorContent').textContent;
    assert(/log source is running/i.test(text), `the box advised: ${text}`);
});

check('a role that may not see the index names is told how many', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.showError('none', 'no_accessible_containers', { total_containers: 3 });
    const text = w.document.getElementById('errorContent').textContent;
    assert(text.includes('3 exist that your role cannot read'), text);
});

check("Elasticsearch's numbers are shown as numbers", () => {
    const w = makeWindow();
    const search = new w.__LogSearch();
    search.displayResults({ records: [], total: '<img id=planted3>',
                            took_ms: '<img id=planted4>', accessible_containers: [] });
    search.renderFieldStats({ fields: [{ field: 'level', values: [
        { value: 'INFO', count: '<img id=planted5>' }] }] });
    search.renderSourceBreakdown({ sources: [
        { name: 'a', count: '<img id=planted6>', total: 1 },
        { name: 'b', count: 1, total: 1 }] });
    ['planted3', 'planted4', 'planted5', 'planted6'].forEach(id =>
        assert(!w.document.getElementById(id), `${id} became an element`));
});

check('a notification is text', () => {
    const w = makeWindow();
    w.__WDash.showNotification('Search saved: <img id=planted7>', 'success');
    assert(!w.document.getElementById('planted7'), 'the name became markup');
    assert(w.document.body.textContent.includes('Search saved: <img id=planted7>'),
           'the text is missing');
});

check('values inside attributes cannot close them', () => {
    const w = makeWindow();
    const search = new w.__LogSearch();
    search.showSources = true;
    const record = { ...RECORD, severity: 'x" data-planted-a="1',
                     severity_text: 'x" style="position:fixed" data-planted-b="1',
                     source: 'es" data-planted-c="1' };
    const row = search.createLogEntry(record);
    const level = row.querySelector('.log-level');
    assert(level && level.getAttribute('style') === null, level && level.outerHTML);
    ['data-planted-a', 'data-planted-b', 'data-planted-c'].forEach(name =>
        assert(!row.querySelector(`[${name}]`), `${name} was written: ${row.innerHTML}`));

    Object.create(w.__LogSearch.prototype).showLogModal(record);
    assert(!w.document.querySelector('#logModalTitle [data-planted-a]'),
           w.document.getElementById('logModalTitle').innerHTML);

    const holder = w.document.createElement('div');
    holder.innerHTML = search._renderContextLog(record, false);
    assert(!holder.querySelector('[data-planted-a]'), holder.innerHTML);
});

check('a value clicked in the sidebar is one value in the query', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.renderFieldStats({ fields: [{ field: 'service', values: [
        { value: 'x" OR service:"hr-salaries', count: 1 },
        { value: 'C:\\temp\\', count: 1 }] }] });
    const filters = [...w.document.querySelectorAll('[data-sidebar-filter]')]
        .map(el => el.dataset.sidebarFilter);
    assertEqual(filters[0], 'service:"x\\" OR service:\\"hr-salaries"',
                'the quote closed the string');
    assertEqual(filters[1], 'service:"C:\\\\temp\\\\"',
                'the backslash escaped the closing quote');
});

check("a record's field value is one value in the query too", () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.showLogModal({ ...RECORD, resource: { host: 'C:\\temp\\' } });
    const clause = [...w.document.querySelectorAll('[data-filter]')]
        .map(el => el.dataset.filter).find(q => q.startsWith('host:'));
    assertEqual(clause, 'host:"C:\\\\temp\\\\"', 'the backslash was left bare');
});

check('a filter added to a query with OR applies to all of it', () => {
    for (const [query, expected] of [
            ['level:ERROR OR level:WARN', '(level:ERROR OR level:WARN) AND service:"api"'],
            ['level:ERROR or level:WARN', '(level:ERROR or level:WARN) AND service:"api"'],
            ['body:"this or that"', 'body:"this or that" AND service:"api"'],
            ['vendor:oracle', 'vendor:oracle AND service:"api"']]) {
        const w = makeWindow();
        w.document.getElementById('query').value = query;
        const search = Object.create(w.__LogSearch.prototype);
        search.performSearch = () => {};
        search._applyFieldFilter('service:"api"');
        assertEqual(w.document.getElementById('query').value, expected, query);
    }
});

check('SUCCESS and NOTICE keep the chips the stylesheet gives them', () => {
    const w = makeWindow();
    const search = new w.__LogSearch();
    for (const [text, level, expected] of [['SUCCESS', 'UNSPECIFIED', 'SUCCESS'],
                                           ['notice', 'INFO', 'NOTICE'],
                                           ['warning-ish', 'WARN', 'WARN']]) {
        const row = search.createLogEntry({ ...RECORD, severity: level,
                                            severity_text: text });
        assertEqual(row.querySelector('.log-level').className,
                    'log-level ' + expected, `${text} / ${level}`);
    }
});

check('the log level class comes from the level, not the text beside it', () => {
    const w = makeWindow();
    const row = new w.__LogSearch().createLogEntry(
        { ...RECORD, severity: 'WARN', severity_text: 'warning-ish' });
    assertEqual(row.querySelector('.log-level').className, 'log-level WARN',
                'the class followed the raw text');
});

// --- field statistics that a source cannot provide -----------------------

check('a source that cannot answer says why, rather than nothing', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.renderFieldStats({
        unsupported: true,
        reason: 'lab-loki does not provide field statistics.',
    });
    const text = w.document.getElementById('fieldStatsContent').textContent;
    assert(text.includes('lab-loki'), `no reason shown: ${text}`);
    // "No field data available" beside a page full of logs reads as a bug in
    // WDash; the reason reads as a property of the backend.
    assert(!text.includes('No field data available'),
           'a capability gap was rendered as missing data');
});

check('a source that can answer still renders its fields', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.renderFieldStats({
        fields: [{ field: 'level', values: [{ value: 'INFO', count: 12 }] }],
    });
    const text = w.document.getElementById('fieldStatsContent').textContent;
    assert(text.includes('INFO') && text.includes('12'), text);
});

check('a source that CAN answer and has nothing says so differently', () => {
    // A quiet window and a missing capability are different facts.
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.renderFieldStats({ fields: [] });
    const text = w.document.getElementById('fieldStatsContent').textContent;
    assert(text.includes('No field data available'), text);
});

// --- the source breakdown ------------------------------------------------

function breakdown(sources, w) {
    const search = Object.create(w.__LogSearch.prototype);
    search.renderSourceBreakdown({ sources });
    const card = w.document.getElementById('sourceBreakdownCard');
    return {
        hidden: card.classList.contains('d-none'),
        text: w.document.getElementById('sourceBreakdownContent')
                .textContent.replace(/\s+/g, ' ').trim(),
    };
}

check('one healthy source says nothing worth a panel', () => {
    const out = breakdown([{ name: 'es', count: 12, total: 900, exact: true }],
                          makeWindow());
    assert(out.hidden, 'showed a breakdown of one');
});

check('a merged search attributes every row', () => {
    const out = breakdown([
        { name: 'es', count: 29, total: 1204, exact: true },
        { name: 'loki', count: 21, total: 21, exact: false },
    ], makeWindow());
    assert(!out.hidden, 'hid the breakdown of two sources');
    assert(out.text.includes('es') && out.text.includes('loki'),
           `missing a source: ${out.text}`);
    // Separator-agnostic: toLocaleString follows the host locale, and the
    // assertion is about "the exact total is stated", not about punctuation.
    assert(/1[.,]?204 matched/.test(out.text), `no exact total: ${out.text}`);
    // The distinction that makes the number safe to reason about.
    assert(/[\u2265>]=?\s*21/.test(out.text),
           `an uncountable total was reported as exact: ${out.text}`);
});

check('a source that did not answer never reads as zero', () => {
    const out = breakdown([
        { name: 'es', count: 50, total: 1204, exact: true },
        { name: 'loki', count: 0, total: 0, failed: true },
    ], makeWindow());
    assert(!out.hidden, 'hid a failure');
    assert(out.text.includes('no answer'),
           `a failure rendered as a count: ${out.text}`);
    assert(!/loki[^a-z]*0 matched/.test(out.text),
           `a failure claimed zero matches: ${out.text}`);
});

check('a lone source that failed is still shown', () => {
    // The "one source is noise" shortcut must not swallow the one case where
    // a single source has something to say.
    const out = breakdown([{ name: 'loki', count: 0, total: 0, failed: true }],
                          makeWindow());
    assert(!out.hidden, 'hid the only source, and it had failed');
});

check('a page with no breakdown does not throw', () => {
    const w = makeWindow();
    const search = Object.create(w.__LogSearch.prototype);
    search.renderSourceBreakdown({});
    assert(w.document.getElementById('sourceBreakdownCard')
             .classList.contains('d-none'), 'showed an empty breakdown');
});

// --- the JSON highlighter must not alter the text -----------------------

check('highlighting never changes the text it colours', () => {
    const w = makeWindow();
    const WDash = w.__WDash;
    const samples = [
        { '@timestamp': '2026-08-04T09:30:12.142Z', ratio: '3:2' },
        { url: 'https://example.com/a?x=1', msg: 'failed: timeout' },
        { n: 42, f: -3.5, e: 1.2e-9, ok: true, bad: false, none: null },
        { quoted: 'he said "hi"', escaped: 'a\\b', markup: '<b>&amp;</b>' },
        { nested: { list: [1, 'two', null, { k: 'v:1' }] } },
    ];
    samples.forEach((sample, i) => {
        const json = JSON.stringify(sample, null, 2);
        const holder = w.document.createElement('div');
        holder.innerHTML = WDash.highlightJson(json);
        assertEqual(holder.textContent, json,
                    `sample ${i + 1}: highlighting corrupted the text`);
        assert(holder.querySelectorAll('span').length > 0,
               `sample ${i + 1}: nothing was highlighted at all`);
    });
});

// --- only a flash closes itself -----------------------------------------
//
// Every success and info box on any page closed after five seconds, flash
// or not: the traces page's scope notice, the advisor's "No findings", the
// setup and roles notes. Measured: the scope notice was gone at 5.1s.

check('only what the layout marks as a flash closes itself', () => {
    const dom = new JSDOM(`<!doctype html><body>
        <div class="alert alert-success alert-dismissible" data-autodismiss id="flash">Saved</div>
        <div class="alert alert-danger alert-dismissible" data-autodismiss id="failed">No</div>
        <div class="alert alert-info" id="scope">Your role can see spans from: api-*</div>
        <div class="alert alert-success" id="nofindings">No findings</div>
        </body>`, { runScripts: 'outside-only' });
    const w = dom.window;
    const closed = new Set();
    w.bootstrap = { Alert: class { constructor(el) { this.el = el; }
                                   close() { closed.add(this.el.id); } },
                    Tooltip: class {} };
    const timers = [];
    w.setTimeout = (fn) => { timers.push(fn); return timers.length; };
    w.eval(fs.readFileSync(path.join(ROOT, 'static/js/wdash.min.js'), 'utf8') +
           '\n; window.__WDash = WDash;');
    w.__WDash.prototype.setupEventListeners.call({});
    timers.forEach(fn => fn());
    assertEqual(JSON.stringify([...closed].sort()), JSON.stringify(['flash']),
                'what had closed after five seconds');
});

// --- paging only where there is a cursor ----------------------------------
//
// Measured on the lab's VictoriaLogs: 2,027 matches, no cursor, and Next
// fetched page one again, labelled "Showing 51-100".

const PAGE = Array.from({ length: 50 }, (_, i) =>
    ({ ...RECORD, ref: 'elasticsearch:app-logs-1:doc-' + i }));

check('Next is offered only when the answer carried a cursor', () => {
    const w = makeWindow();
    const search = new w.__LogSearch();
    search.pageSize = 50;
    search.displayResults({ records: PAGE, total: 5000, cursor: null,
                            accessible_containers: [] });
    const pagination = w.document.getElementById('pagination');
    assert(!w.document.getElementById('paginationNext'),
           `Next with no cursor: ${pagination.textContent}`);
    assert(/narrow the time range/i.test(pagination.textContent),
           `nothing says why there is no next page: ${pagination.textContent}`);

    search.displayResults({ records: PAGE, total: 5000, cursor: [1, 2],
                            accessible_containers: [] });
    assert(w.document.getElementById('paginationNext'), 'no Next with a cursor');
    search.displayResults({ records: PAGE, total: 5000, cursor: null,
                            accessible_containers: [] });
    assert(!w.document.getElementById('paginationNext'),
           'the previous answer\'s cursor was paged with');
});

// --- what a new search, a later page and Clear leave on screen ------------

function histogramWindow() {
    const w = makeWindow();
    w.document.body.insertAdjacentHTML('beforeend',
        '<div class="d-none" id="histogramCard"><canvas id="logHistogram"></canvas>' +
        '<div id="histogramSummary"></div></div>' +
        '<div id="searchWarnings" class="d-none"></div>');
    const charts = { built: 0, destroyed: 0 };
    w.Chart = class { constructor() { charts.built++; }
                      destroy() { charts.destroyed++; } };
    const search = new w.__LogSearch();
    search.pageSize = 1;
    const histogram = [{ timestamp: '2026-09-11T10:00:00Z', count: 2,
                         by_severity: { INFO: 2 } }];
    search.displayResults({ records: [RECORD], total: 2, cursor: [1, 2], histogram,
                            warnings: ['vl: a note'], accessible_containers: [] });
    return { w, search, charts,
             card: w.document.getElementById('histogramCard') };
}

check('an empty search takes away the chart and the pages of the last', () => {
    const { w, search, charts, card } = histogramWindow();
    assert(!card.classList.contains('d-none'), 'the first chart was never drawn');
    assert(w.document.getElementById('paginationNext'), 'no Next on page one');
    search.displayResults({ records: [], total: 0, cursor: null, histogram: [],
                            accessible_containers: [] });
    assert(card.classList.contains('d-none'),
           `the last search's chart stayed: ${w.document.getElementById('histogramSummary').textContent}`);
    assertEqual(charts.destroyed, 1, 'the last chart was not destroyed');
    assertEqual(w.document.getElementById('pagination').textContent.trim(), '',
                'the last search\'s pages stayed');
});

check("a later page keeps the first page's chart", () => {
    // The server sends the histogram with the first page only.
    const { search, card } = histogramWindow();
    search.currentPage = 1;
    search.displayResults({ records: [RECORD], total: 2, cursor: [3, 4],
                            accessible_containers: [] });
    assert(!card.classList.contains('d-none'), 'page two hid the chart');
});

check('Clear takes away the chart, the sources, the warnings and the stats', () => {
    const { w, search, charts, card } = histogramWindow();
    search.renderSourceBreakdown({ sources: [{ name: 'a', count: 1, total: 1 },
                                             { name: 'b', count: 1, total: 1 }] });
    w.document.getElementById('fieldStatsContent').textContent = 'level INFO 2';
    const warnings = w.document.getElementById('searchWarnings');
    assert(!warnings.classList.contains('d-none'), 'the warning was never shown');
    search.clearSearch();
    assert(card.classList.contains('d-none'), 'the chart stayed');
    assertEqual(charts.destroyed, 1, 'the chart was not destroyed');
    assert(w.document.getElementById('sourceBreakdownCard').classList.contains('d-none'),
           'the source breakdown stayed');
    assert(warnings.classList.contains('d-none') && !warnings.textContent.trim(),
           `the warning stayed: ${warnings.textContent}`);
    assert(!w.document.getElementById('fieldStatsContent').textContent.includes('INFO'),
           'the field statistics of the last search stayed');
});

// --- asynchronous assertions --------------------------------------------

(async () => {
    await new Promise(resolve => setTimeout(resolve, 80));

    await new Promise(resolve => {
        const w = makeWindow((url) => url.endsWith('/raw')
            ? Promise.resolve({ ok: true, status: 200,
                json: () => Promise.resolve({ found: true, document: RAW_DOCUMENT }) })
            : new Promise(() => {}));
        const search = Object.create(w.__LogSearch.prototype);
        search.showLogModal(RECORD);
        w.document.getElementById('tabSource').dispatchEvent(new w.Event('click'));

        setTimeout(() => {
            check('the Raw tab content keeps the original field names', () => {
                const text = w.document.getElementById('sourceCode').textContent;
                ['@timestamp', 'level', 'message', 'correlation_id', '_index']
                    .forEach(field => assert(text.includes(`"${field}"`),
                                             `"${field}" missing from the raw view`));
                assert(text.includes('09:30:12'),
                       'the timestamp was mangled by the highlighter');
            });
            resolve();
        }, 60);
    });

    await new Promise(resolve => {
        const w = makeWindow((url) => url.endsWith('/raw')
            ? Promise.resolve({ ok: false, status: 403,
                json: () => Promise.resolve({ error: 'Access denied to this index' }) })
            : new Promise(() => {}));
        const search = Object.create(w.__LogSearch.prototype);
        search.showLogModal(RECORD);
        w.document.getElementById('tabSource').dispatchEvent(new w.Event('click'));

        setTimeout(() => {
            check('a refused raw fetch shows the reason', () => {
                const code = w.document.getElementById('sourceCode');
                assert(code.textContent.includes('Access denied'),
                       `still showing: ${code.textContent}`);
                assert(!code.textContent.includes('Loading'),
                       'left stuck on the loading placeholder');
            });
            resolve();
        }, 60);
    });

    // -----------------------------------------------------------------
    // The theme, which lives inline in base.html
    // -----------------------------------------------------------------
    //
    // Extracted from the template and run, rather than asserted about as
    // text. It has to be inline and in the <head> — a page that renders in
    // one theme and then swaps is worse than one with no choice at all — and
    // that puts it outside every bundle, where nothing was watching it.
    const layout = fs.readFileSync(path.join(ROOT, 'templates/base.html'), 'utf8');
    const themeScript = layout
        .split('<script nonce="{{ csp_nonce }}">')[1]
        .split('</script>')[0];

    function themeWindow({ stored, systemPrefersLight, storageThrows }) {
        const page = new JSDOM('<!doctype html><html><body></body></html>',
                               { runScripts: 'outside-only' });
        const w = page.window;
        const box = { 'wdash-theme': stored };
        // defineProperty, not assignment: jsdom exposes `localStorage` as an
        // accessor on the prototype, so `w.localStorage = {...}` is silently
        // dropped and the script reads the real one — which is empty, so
        // every case looked like "nothing stored" and passed for the default.
        Object.defineProperty(w, 'localStorage', { configurable: true, value: {
            getItem(key) {
                if (storageThrows) throw new Error('storage is off');
                return key in box ? box[key] : null;
            },
            setItem(key, value) {
                if (storageThrows) throw new Error('storage is off');
                box[key] = value;
            },
        } });
        w.matchMedia = query => ({
            matches: query.includes('light') && systemPrefersLight,
            addEventListener() {},
        });
        w.eval(themeScript);
        return w;
    }

    check('nothing stored means dark, which is what is already deployed', () => {
        const w = themeWindow({ stored: undefined, systemPrefersLight: true });
        assertEqual(w.document.documentElement.getAttribute('data-theme'),
                    'dark', 'an upgrade changed how the product looks');
    });

    check('a stored choice is what gets applied', () => {
        const w = themeWindow({ stored: 'light', systemPrefersLight: false });
        assertEqual(w.document.documentElement.getAttribute('data-theme'),
                    'light', 'the stored choice was ignored');
    });

    check('following the system asks the system', () => {
        const light = themeWindow({ stored: 'system', systemPrefersLight: true });
        const dark = themeWindow({ stored: 'system', systemPrefersLight: false });
        assertEqual(light.document.documentElement.getAttribute('data-theme'),
                    'light', 'system + light desktop should be light');
        assertEqual(dark.document.documentElement.getAttribute('data-theme'),
                    'dark', 'system + dark desktop should be dark');
    });

    check('the choice is remembered, not the resolved theme', () => {
        const w = themeWindow({ stored: 'system', systemPrefersLight: true });
        assertEqual(w.document.documentElement.getAttribute('data-theme-choice'),
                    'system',
                    'storing "light" instead would stop following the system');
    });

    check('both theme attributes move together', () => {
        const w = themeWindow({ stored: 'light', systemPrefersLight: false });
        const root = w.document.documentElement;
        assertEqual(root.getAttribute('data-bs-theme'),
                    root.getAttribute('data-theme'),
                    'Bootstrap and the palette disagree, which is a page with '
                    + 'light dropdowns on a dark background');
    });

    check('choosing "follow the system" stores the CHOICE', () => {
        // Storing the resolved theme instead would follow the system exactly
        // once: the next visit reads "light", which is a fixed choice, and
        // the desktop switching to dark at six o'clock does nothing.
        const w = themeWindow({ stored: 'dark', systemPrefersLight: true });
        w.wdashTheme.set('system');
        assertEqual(w.localStorage.getItem('wdash-theme'), 'system',
                    'the stored value stopped being the choice');
        assertEqual(w.document.documentElement.getAttribute('data-theme'),
                    'light', 'the system preference was not applied');
    });

    check('storage being unavailable is not a broken page', () => {
        const w = themeWindow({ stored: 'light', storageThrows: true });
        assertEqual(w.document.documentElement.getAttribute('data-theme'),
                    'dark', 'private browsing should fall back, not throw');
        w.wdashTheme.set('light');
        assertEqual(w.document.documentElement.getAttribute('data-theme'),
                    'light', 'the choice should still apply for this page');
    });

    check('rubbish in storage does not become a theme attribute', () => {
        const w = themeWindow({ stored: 'purple', systemPrefersLight: false });
        assertEqual(w.document.documentElement.getAttribute('data-theme'),
                    'dark', 'an unknown value should fall back to the default');
    });

    // What a canvas is told when the theme changes: once per change, with the
    // theme it changed TO, and not at all when nothing changed — a redraw of
    // every chart for a click on the item already chosen is a flicker.
    check('a theme change is announced, once, with the new theme', () => {
        const w = themeWindow({ stored: 'dark', systemPrefersLight: false });
        const heard = [];
        w.document.addEventListener('wdash:theme',
                                    event => heard.push(event.detail.theme));
        w.wdashTheme.set('light');
        w.wdashTheme.set('light');
        w.wdashTheme.set('system');          // resolves to dark here
        assertEqual(JSON.stringify(heard), JSON.stringify(['light', 'dark']),
                    'announcements did not follow the changes');
    });

    // -----------------------------------------------------------------
    // The log histogram's colours
    // -----------------------------------------------------------------
    //
    // Its axis and legend text were left to Chart.js, which paints them its
    // built-in #666 — 2.2:1 on the dark page, and on a canvas, where the
    // contrast suite cannot see. And a theme switch left every bar in the
    // colours it was first drawn in.
    check('the histogram takes its text and bars from the palette, and ' +
          'draws again when the theme changes', () => {
        const w = makeWindow();
        w.document.body.insertAdjacentHTML('beforeend',
            '<div class="d-none" id="histogramCard"><canvas id="logHistogram">' +
            '</canvas><div id="histogramSummary"></div></div>');
        const built = [];
        w.Chart = class { constructor(canvas, config) { built.push(config); }
                          destroy() {} };
        const root = w.document.documentElement;
        root.style.setProperty('--text-muted', '#111111');
        root.style.setProperty('--text-primary', '#222222');
        root.style.setProperty('--fill-red', '#333333');
        const search = new w.__LogSearch();
        search.renderHistogram({ histogram: [
            { timestamp: '2026-09-11T10:00:00Z', count: 4,
              by_severity: { ERROR: 4 } }] });
        assertEqual(built.length, 1, 'no chart was built');
        const first = built[0];
        assertEqual(first.options.scales.x.ticks.color, '#111111',
                    'the x axis is not palette ink');
        assertEqual(first.options.scales.y.ticks.color, '#111111',
                    'the y axis is not palette ink');
        assertEqual(first.options.plugins.legend.labels.color, '#222222',
                    'the legend is not palette ink');
        assertEqual(first.data.datasets[0].backgroundColor, '#333333',
                    'ERROR is not the palette red');

        root.style.setProperty('--text-muted', '#444444');
        root.style.setProperty('--fill-red', '#555555');
        w.document.dispatchEvent(new w.CustomEvent('wdash:theme',
                                                   { detail: { theme: 'light' } }));
        assertEqual(built.length, 2, 'a theme change did not draw it again');
        assertEqual(built[1].options.scales.x.ticks.color, '#444444',
                    'redrawn in the old colours');
        assertEqual(built[1].data.datasets[0].backgroundColor, '#555555',
                    'the bars kept the old red');
    });

    // The saved-search list: its attributes too.
    {
        const w = makeWindow(() => Promise.resolve({ ok: true, json: () =>
            Promise.resolve([{ id: 'y" data-planted-d="1', name: 'n', query: 'q',
                               time_range: 'x" data-planted-e="1' }]) }));
        const search = Object.create(w.__LogSearch.prototype);
        await search._loadSavedSearches();
        check('a saved search cannot write its own attributes', () => {
            const list = w.document.getElementById('savedSearchList');
            assert(!list.querySelector('[data-planted-d]')
                   && !list.querySelector('[data-planted-e]'), list.innerHTML);
            assertEqual(list.querySelector('.saved-search-apply').dataset.time,
                        'x" data-planted-e="1', 'the time range did not survive');
        });
    }

    // Field statistics that failed. The sidebar rendered whatever came back,
    // status unread, and a 503 read as "No field data available" beside a
    // page of results.
    {
        const w = makeWindow((url) => url.startsWith('/api/field-stats')
            ? Promise.resolve({ ok: false, status: 503, json: () => Promise.resolve({
                error: 'es could not answer: read timed out',
                error_type: 'backend_error' }) })
            : new Promise(() => {}));
        await Object.create(w.__LogSearch.prototype).loadFieldStats();
        check('field statistics that failed say so', () => {
            const text = w.document.getElementById('fieldStatsContent').textContent;
            assert(/could not be loaded/i.test(text) && text.includes('read timed out'),
                   `said: ${text}`);
            assert(!text.includes('No field data available'),
                   'a failure was shown as no data');
        });
    }
    check('a merged sidebar names the source whose statistics failed', () => {
        const w = makeWindow();
        Object.create(w.__LogSearch.prototype).renderFieldStats({
            fields: [{ field: 'level', values: [{ value: 'INFO', count: 3 }] }],
            partial: true, failed_sources: ['es-b'] });
        const text = w.document.getElementById('fieldStatsContent').textContent;
        assert(text.includes('es-b') && text.includes('INFO'), `said: ${text}`);
    });

    // Counts computed from the shards that answered. The numbers are real and
    // the window they cover is not the one on screen, so they are shown with
    // the reason above them rather than instead of them.
    check('counts drawn from part of the data say so', () => {
        const w = makeWindow();
        Object.create(w.__LogSearch.prototype).renderFieldStats({
            fields: [{ field: 'level', values: [{ value: 'INFO', count: 3 }] }],
            partial: true,
            warnings: ['5 of 6 shards failed: <img src=x> For input string'] });
        const el = w.document.getElementById('fieldStatsContent');
        assert(el.textContent.includes('5 of 6 shards failed'),
               `said: ${el.textContent}`);
        assert(el.textContent.includes('INFO'), 'the counts were thrown away');
        assert(!el.querySelector('img'), 'the backend closed the attribute');
    });

    // An empty saved-search list that is really an unmigrated one.
    //
    // /api/saved-searches answers `[]` for "you have never saved one" and for
    // "yours are in a JSON file this installation stopped reading", and the
    // dropdown printed "No saved searches yet" over both — a failure wearing
    // the clothes of emptiness. The server puts what it found on the list
    // element, so the API's shape does not have to change.
    {
        const empty = () => Promise.resolve({ ok: true, json: () => Promise.resolve([]) });

        const plain = makeWindow(empty);
        await Object.create(plain.__LogSearch.prototype)._loadSavedSearches();
        check('an empty list with nothing left behind still says so plainly', () => {
            const text = plain.document.getElementById('savedSearchList').textContent;
            assertEqual(text.trim(), 'No saved searches yet', text);
        });

        const behind = makeWindow(empty);
        behind.document.getElementById('savedSearchList').dataset.leftBehind =
            '2 saved searches are in a JSON file that nothing is reading';
        await Object.create(behind.__LogSearch.prototype)._loadSavedSearches();
        check('an empty list that is really an unmigrated one says which', () => {
            const el = behind.document.getElementById('savedSearchList');
            assert(el.textContent.includes('2 saved searches are in a JSON file'),
                   `said: ${el.textContent}`);
            assert(!el.textContent.includes('No saved searches yet'),
                   'it said both');
        });

        const hostile = makeWindow(empty);
        hostile.document.getElementById('savedSearchList').dataset.leftBehind =
            '<img src=x onerror="window.__planted=1">';
        await Object.create(hostile.__LogSearch.prototype)._loadSavedSearches();
        check('the empty state cannot write its own markup', () => {
            const el = hostile.document.getElementById('savedSearchList');
            assert(!el.querySelector('img'), el.innerHTML);
        });
    }

    console.log(failures.length
        ? `\n${failures.length} failure(s)`
        : '\nall front-end smoke checks passed');
    process.exit(failures.length ? 1 : 0);
})();
