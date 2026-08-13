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
          <select id="timeRange"><option value="1h" selected>1h</option>
          <option value="custom">custom</option></select>
          <input id="startTime"><input id="endTime">
          <div id="customStartGroup"></div><div id="customEndGroup"></div>
        </form>
        <div id="resultsInfo"></div><div id="pagination"></div>
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

    console.log(failures.length
        ? `\n${failures.length} failure(s)`
        : '\nall front-end smoke checks passed');
    process.exit(failures.length ? 1 : 0);
})();
