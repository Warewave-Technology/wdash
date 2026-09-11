/**
 * The trace page's empty lists.
 *
 * An empty list has two different meanings here: nothing happened in the time
 * range, or the role reaches no trace store in this source. The server tells
 * them apart and says which; these checks hold that the page repeats it
 * rather than printing "No traces match." for both — a missing grant that
 * reads as a quiet hour is the kind of failure that looks like emptiness.
 *
 * The script is taken from templates/traces.html as it is, so there is no
 * copy of it here to drift.
 *
 * Run: npm test
 */

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const ROOT = path.join(__dirname, '..');
const failures = [];

function check(name, condition, detail) {
    if (typeof condition === 'function') {
        throw new Error(`check("${name}") was given a function; it takes a BOOLEAN.`);
    }
    if (condition) {
        console.log(`  ok    ${name}`);
    } else {
        failures.push(name);
        console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`);
    }
}

const template = fs.readFileSync(path.join(ROOT, 'templates/traces.html'), 'utf8');
const script = template.match(/<script nonce="\{\{ csp_nonce \}\}">([\s\S]*?)<\/script>/);
if (!script) {
    console.log('  FAIL  the page script was not found in templates/traces.html');
    process.exit(1);
}

/** The page, with the server answering `services` and `traces`. */
function build(services, traces) {
    const dom = new JSDOM(`<!doctype html><body>
      <select id="timeRange"><option value="24h" selected>24h</option></select>
      <span id="spanTotal"></span><div id="serviceList"></div>
      <span id="traceListTitle"></span>
      <input id="traceIdInput"><button id="lookupBtn"></button>
      <select id="sortBy"><option value="recent" selected>recent</option></select>
      <input type="checkbox" id="errorsOnly">
      <div id="traceList"></div></body>`,
      { runScripts: 'outside-only', url: 'http://localhost/traces' });
    const w = dom.window;
    w.fetch = (url) => Promise.resolve({
        ok: true,
        json: () => Promise.resolve(url.startsWith('/api/traces/services')
                                    ? services : traces) });
    w.eval(script[1]);
    return w;
}

const settle = () => new Promise(resolve => setTimeout(resolve, 20));

(async () => {
    const explained = 'Your role reaches no trace store in lab-tempo.';
    const closed = build(
        { services: [], error_type: 'no_accessible_trace_stores', suggestion: explained },
        { traces: [], error_type: 'no_accessible_trace_stores', suggestion: explained });
    await settle();
    const serviceSaid = closed.document.getElementById('serviceList').textContent;
    const traceSaid = closed.document.getElementById('traceList').textContent;
    check('an empty service list says why, when the server knows',
          serviceSaid.includes(explained), serviceSaid);
    check('an empty trace list says why, when the server knows',
          traceSaid.includes(explained), traceSaid);

    const quiet = build({ services: [], total_spans: 0 }, { traces: [] });
    await settle();
    check('an empty trace list with nothing to explain says so plainly',
          quiet.document.getElementById('traceList').textContent
              .includes('No traces match.'));

    const hostile = build({ services: [] },
                          { traces: [], suggestion: '<img src=x id=planted>' });
    await settle();
    check('the explanation is text, not markup',
          !hostile.document.getElementById('planted'));

    console.log(failures.length ? `\n${failures.length} failure(s)`
                                : '\nall trace page checks passed');
    process.exit(failures.length ? 1 : 0);
})();
