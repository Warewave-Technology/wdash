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

/** An answer: a bare body is a 200; `{status, body}` says otherwise. */
function answer(reply) {
    const status = reply && reply.status ? reply.status : 200;
    const body = reply && reply.status ? reply.body : reply;
    return Promise.resolve({ ok: status < 400, status,
                             json: () => Promise.resolve(body) });
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
    w.fetch = (url) => answer(url.startsWith('/api/traces/services')
                              ? services : traces);
    w.eval(script[1]);
    return w;
}

// ------------------------------------------------------------ the trace page

const detailTemplate = fs.readFileSync(
    path.join(ROOT, 'templates/trace_detail.html'), 'utf8');
const detailMatch = detailTemplate.match(
    /<script nonce="\{\{ csp_nonce \}\}">([\s\S]*?)<\/script>/);
if (!detailMatch) {
    console.log('  FAIL  the page script was not found in templates/trace_detail.html');
    process.exit(1);
}
/** What the server fills into the script. An expression not listed here
 * fails the run, so a template change cannot be run half-rendered. */
const RENDERED = {
    "trace_id|tojson": '"trace-1"',
    "(request.args.get('source') or '')|tojson": '""',
    "'true' if can_read_logs else 'false'": 'true',
};
const detailScript = detailMatch[1].replace(/\{\{\s*(.*?)\s*\}\}/g, (all, expression) => {
    if (!(expression in RENDERED)) {
        console.log(`  FAIL  trace_detail.html has an expression this suite does not render: ${all}`);
        process.exit(1);
    }
    return RENDERED[expression];
});

function span(id, parent, service, status) {
    return { trace_id: 'trace-1', span_id: id, parent_span_id: parent, name: 'op',
             service, kind: 'SERVER', status: status || 'OK',
             start: '2026-09-11T10:00:00.000Z', duration_us: 1000,
             resource: {}, attributes: {} };
}

const TRACE = {
    trace_id: 'trace-1', duration_us: 1000, services: ['api-gateway', 'payments'],
    has_error: false, partial: false, warnings: [], scoped: false,
    spans: [span('a', null, 'api-gateway'), span('b', 'a', 'payments')],
    waterfall: [{ span_id: 'a', depth: 0, self_time_us: 0 },
                { span_id: 'b', depth: 1, self_time_us: 1000 }],
    service_breakdown: [{ service: 'payments', self_time_us: 1000, share: 1,
                          span_count: 1, error_count: 0 }],
};

/** The trace page, with the server answering the trace and its logs. */
function buildDetail(trace, logs) {
    const dom = new JSDOM(`<!doctype html><body>
      <select id="timeRange"><option value="24h" selected>24h</option></select>
      <div id="summary"></div><div id="alerts"></div>
      <div id="breakdown"></div><div id="spanDetail"></div>
      <div id="waterfall"></div>
      <span id="logCount"></span><div id="correlatedLogs"></div></body>`,
      { runScripts: 'outside-only', url: 'http://localhost/traces/trace-1' });
    const w = dom.window;
    w.fetch = (url) => answer(url.includes('/logs?') ? logs : trace);
    w.eval(detailScript);
    return w;
}

const text = (w, id) => w.document.getElementById(id).textContent;

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

    // --- a backend that could not answer ---

    const missing = 'down-jaeger failed: connection refused';
    const row = { trace_id: 'abcdef0123456789abcd', service: 'api-gateway', name: 'GET /',
                  start: '2026-09-11T10:00:00.000Z', duration_us: 1200, has_error: false,
                  source: 'live' };
    const partly = build(
        { services: [{ name: 'api-gateway', span_count: 3, error_count: 0, error_rate: 0 }],
          total_spans: 3, partial: true, warnings: [missing] },
        { traces: [row], partial: true, warnings: [missing] });
    await settle();
    check('a partial service list names what is missing',
          text(partly, 'serviceList').includes(missing) &&
          text(partly, 'serviceList').includes('api-gateway'), text(partly, 'serviceList'));
    check('a partial trace list names what is missing',
          text(partly, 'traceList').includes(missing) &&
          partly.document.querySelectorAll('.trace-row').length === 1,
          text(partly, 'traceList'));

    const complete = build(
        { services: [{ name: 'api-gateway', span_count: 3, error_count: 0, error_rate: 0 }],
          total_spans: 3, partial: false, warnings: [] },
        { traces: [row], partial: false, warnings: [] });
    await settle();
    check('a complete list says nothing is missing',
          !text(complete, 'serviceList').includes('could not') &&
          !text(complete, 'traceList').includes('could not'));

    const emptyPartly = build(
        { services: [], partial: true, warnings: [missing] },
        { traces: [], partial: true, warnings: [missing] });
    await settle();
    check('an empty partial service list is not "no spans"',
          text(emptyPartly, 'serviceList').includes(missing) &&
          !text(emptyPartly, 'serviceList').includes('No spans in this time range'),
          text(emptyPartly, 'serviceList'));
    check('an empty partial trace list is not "no traces match"',
          text(emptyPartly, 'traceList').includes(missing) &&
          !text(emptyPartly, 'traceList').includes('No traces match'),
          text(emptyPartly, 'traceList'));

    const down = build(
        { status: 503, body: { error: 'Unable to load services.',
                               error_type: 'trace_source_error',
                               details: 'Jaeger answered HTTP 503: storage down' } },
        { status: 503, body: { error: 'Unable to search traces.',
                               error_type: 'trace_source_error',
                               details: 'Jaeger answered HTTP 503: storage down' } });
    await settle();
    check('a backend that is down says why on the service list',
          text(down, 'serviceList').includes('Unable to load services.') &&
          text(down, 'serviceList').includes('storage down'), text(down, 'serviceList'));
    check('a backend that is down says why on the trace list',
          text(down, 'traceList').includes('Unable to search traces.') &&
          text(down, 'traceList').includes('storage down'), text(down, 'traceList'));

    const plantedWarning = build({ services: [], partial: true,
                                   warnings: ['<img src=x id=planted2>'] },
                                 { traces: [], partial: true,
                                   warnings: ['<img src=x id=planted3>'] });
    await settle();
    check('a warning is text, not markup',
          !plantedWarning.document.getElementById('planted2') &&
          !plantedWarning.document.getElementById('planted3'));

    // --- the trace page ---

    const halfTrace = buildDetail(
        Object.assign({}, TRACE, { partial: true, warnings: [missing] }),
        { records: [], total: 0, partial: false, warnings: [] });
    await settle();
    check('a partial trace names the store that did not answer',
          text(halfTrace, 'alerts').includes('Part of this trace could not be read') &&
          text(halfTrace, 'alerts').includes(missing), text(halfTrace, 'alerts'));

    const wholeTrace = buildDetail(TRACE, { records: [], total: 0, partial: false,
                                            warnings: [] });
    await settle();
    check('a whole trace carries no partial banner',
          !text(wholeTrace, 'alerts').includes('could not be read'));
    check('logs that do not carry the id are explained as such',
          text(wholeTrace, 'correlatedLogs').includes('No log records carry this trace id'),
          text(wholeTrace, 'correlatedLogs'));

    const logsFailed = buildDetail(TRACE, {
        records: [], total: 0, partial: true,
        warnings: ['search failed: log cluster unreachable'] });
    await settle();
    check('a failed log search says it failed, and why',
          text(logsFailed, 'correlatedLogs').includes('The log search failed') &&
          text(logsFailed, 'correlatedLogs').includes('log cluster unreachable') &&
          !text(logsFailed, 'correlatedLogs').includes('Logs need a'),
          text(logsFailed, 'correlatedLogs'));

    const explainedLogs = buildDetail(TRACE, {
        records: [], total: 0, partial: false,
        warnings: ['the scope permits no containers'] });
    await settle();
    check('an empty log answer with a reason gives the reason, not a failure',
          text(explainedLogs, 'correlatedLogs').includes('the scope permits no containers') &&
          !text(explainedLogs, 'correlatedLogs').includes('failed') &&
          !text(explainedLogs, 'correlatedLogs').includes('Logs need a'),
          text(explainedLogs, 'correlatedLogs'));

    const traceDown = buildDetail(
        { status: 503, body: { error: 'Unable to load trace.',
                               error_type: 'trace_source_error',
                               details: 'Tempo answered HTTP 502: bad gateway' } },
        { records: [] });
    await settle();
    check('a trace that could not be loaded says why',
          text(traceDown, 'alerts').includes('Unable to load trace.') &&
          text(traceDown, 'alerts').includes('bad gateway'), text(traceDown, 'alerts'));

    const noLogSource = buildDetail(TRACE, {
        status: 503, body: { records: [], error_type: 'no_source' } });
    await settle();
    check('no log source is said, not blamed on a missing field',
          text(noLogSource, 'correlatedLogs').includes('No log source') &&
          !text(noLogSource, 'correlatedLogs').includes('Logs need a'),
          text(noLogSource, 'correlatedLogs'));

    const logError = buildDetail(TRACE, {
        status: 503, body: { records: [], error_type: 'log_source_error',
                             details: 'ConnectionTimeout after 30s' } });
    await settle();
    check('a log source error carries its reason',
          text(logError, 'correlatedLogs').includes('ConnectionTimeout after 30s') &&
          !text(logError, 'correlatedLogs').includes('Logs need a'),
          text(logError, 'correlatedLogs'));

    const someLogs = buildDetail(TRACE, {
        records: [{ timestamp: '2026-09-11T10:00:00.000Z', severity: 'INFO',
                    severity_text: 'INFO', service: 'payments', body: 'charged' }],
        total: 1, partial: true, warnings: ['loki failed: timed out'] });
    await settle();
    check('the records of a partial log search are shown with what is missing',
          text(someLogs, 'correlatedLogs').includes('charged') &&
          text(someLogs, 'correlatedLogs').includes('loki failed: timed out'),
          text(someLogs, 'correlatedLogs'));

    const plantedLog = buildDetail(
        Object.assign({}, TRACE, { partial: true, warnings: ['<img src=x id=planted4>'] }),
        { records: [], total: 0, partial: true, warnings: ['<img src=x id=planted5>'] });
    await settle();
    check('the trace page\'s warnings are text, not markup',
          !plantedLog.document.getElementById('planted4') &&
          !plantedLog.document.getElementById('planted5'));

    const plantedMore = [
        buildDetail(TRACE, { records: [], total: 0, partial: false,
                             warnings: ['<img src=x id=planted6>'] }),
        buildDetail(TRACE, {
            records: [{ timestamp: '2026-09-11T10:00:00.000Z', severity: 'INFO',
                        severity_text: 'INFO', service: 'payments', body: 'ok' }],
            total: 1, partial: true, warnings: ['<img src=x id=planted7>'] }),
        buildDetail({ status: 503, body: { error: 'Unable to load trace.',
                                           details: '<img src=x id=planted8>' } },
                    { records: [] }),
        buildDetail(TRACE, { status: 503, body: { records: [],
                                                  error_type: 'log_source_error',
                                                  details: '<img src=x id=planted9>' } }),
    ];
    await settle();
    check('every other warning on the trace page is text too',
          plantedMore.every(w => !w.document.querySelector('[id^=planted]')));

    console.log(failures.length ? `\n${failures.length} failure(s)`
                                : '\nall trace page checks passed');
    process.exit(failures.length ? 1 : 0);
})();
