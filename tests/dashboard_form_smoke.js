/**
 * The dashboard forms' "Test query" button.
 *
 * It never worked. It sent no time range, which the search API refuses, so
 * every test answered "A time range is required"; and its success branch read
 * `hits` and `_source`, which the API stopped sending when it moved to the
 * neutral model. What did reach the page reached it as markup: the error
 * quotes the query and the role's name back, and a record's index and body
 * are whatever was written.
 *
 * The script is taken from each template as it is, so there is no copy of it
 * here to drift.
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

function script(template) {
    const text = fs.readFileSync(path.join(ROOT, 'templates', template), 'utf8');
    const found = text.match(/<script nonce="\{\{ csp_nonce \}\}">([\s\S]*?)<\/script>/);
    if (!found) throw new Error(`no page script in ${template}`);
    return found[1];
}

/**
 * The form, with the search API answering `answer` (or failing).
 *
 * `sourceValue` is what the Log source select is left on — '' being the
 * default, and `null` the deployment with one source configured, where the
 * template renders no select at all.
 */
function build(template, answer, sourceValue = null) {
    const select = sourceValue === null ? '' :
        `<select id="source">
           <option value="" ${sourceValue ? '' : 'selected'}>Default (es)</option>
           <option value="lab-victorialogs" ${sourceValue ? 'selected' : ''}>vl</option>
         </select>`;
    const dom = new JSDOM(`<!doctype html><body>
      <input id="query" value="level:ERROR">${select}
      <div><select id="index_patterns" multiple>
        <option value="*" selected>*</option></select></div>
      <button id="testQuery"></button><div id="testResults"></div></body>`,
      { runScripts: 'outside-only', url: 'http://localhost/dashboard/create' });
    const w = dom.window;
    const asked = [];
    w.alert = () => {};
    w.fetch = (url) => {
        asked.push(url);
        return answer instanceof Error ? Promise.reject(answer)
            : Promise.resolve({ json: () => Promise.resolve(answer) });
    };
    w.eval(script(template));
    return { w, asked };
}

const settle = () => new Promise(resolve => setTimeout(resolve, 20));

(async () => {
    for (const template of ['dashboard_create.html', 'dashboard_edit.html']) {
        console.log(template);

        const found = build(template, {
            total: 2, records: [
                { timestamp: '2026-09-11T10:00:00Z', ref: 'es:app-<b id=planted1>:1',
                  body: 'boom <img src=x id=planted2>' },
                { timestamp: '2026-09-11T10:01:00Z', ref: 'es:app-logs:2', body: 'ok' }] });
        found.w.document.getElementById('testQuery').click();
        await settle();
        const said = found.w.document.getElementById('testResults');
        const sent = new URL(found.asked[0], 'http://localhost').searchParams;
        check('it asks with a time range the search API accepts',
              sent.get('start_time') && sent.get('end_time')
              && new Date(sent.get('end_time')) > new Date(sent.get('start_time')),
              found.asked[0]);
        check('it shows the records the API sends',
              said.textContent.includes('2 matching')
              && said.textContent.includes('app-logs'), said.textContent);
        check('an index and a body are text',
              !found.w.document.getElementById('planted1')
              && !found.w.document.getElementById('planted2'), said.innerHTML);

        const refused = build(template, {
            error: 'Your role "<img src=x id=planted3>" does not have access',
            records: [] });
        refused.w.document.getElementById('testQuery').click();
        await settle();
        check('an error is text',
              !refused.w.document.getElementById('planted3')
              && refused.w.document.getElementById('testResults')
                  .textContent.includes('Your role "<img'),
              refused.w.document.getElementById('testResults').innerHTML);

        const broken = build(template, new Error('<img id=planted4>'));
        broken.w.document.getElementById('testQuery').click();
        await settle();
        check('a failed request is text',
              !broken.w.document.getElementById('planted4'),
              broken.w.document.getElementById('testResults').innerHTML);

        // The button sent q, size and the window and nothing else, so the
        // test always ran against the DEFAULT source whatever the Source
        // select said — /api/search takes `source` and would have honoured
        // it. Measured on the demo over 2026-09-11..09-12: the default
        // answered 30,647 where the selected VictoriaLogs holds 1,742.
        const chosen = build(template, {
            total: 1742, records: [],
            sources: [{ name: 'lab-victorialogs', exact: true }] },
            'lab-victorialogs');
        chosen.w.document.getElementById('testQuery').click();
        await settle();
        const asked = new URL(chosen.asked[0], 'http://localhost').searchParams;
        check('it tests the source the form has selected',
              asked.get('source') === 'lab-victorialogs', chosen.asked[0]);
        check('and says which store answered',
              chosen.w.document.getElementById('testResults')
                  .textContent.includes('lab-victorialogs'),
              chosen.w.document.getElementById('testResults').textContent);

        const byDefault = build(template, {
            total: 30647, records: [],
            sources: [{ name: 'elasticsearch-logs', exact: true }] }, '');
        byDefault.w.document.getElementById('testQuery').click();
        await settle();
        check('the default is left unnamed rather than guessed at',
              !new URL(byDefault.asked[0], 'http://localhost')
                  .searchParams.has('source'), byDefault.asked[0]);

        const alone = build(template, {
            total: 7, records: [], sources: [{ name: 'es', exact: true }] });
        alone.w.document.getElementById('testQuery').click();
        await settle();
        check('a deployment with one source has no select and still tests',
              !new URL(alone.asked[0], 'http://localhost')
                  .searchParams.has('source')
              && alone.w.document.getElementById('testResults')
                  .textContent.includes('7 matching'),
              alone.w.document.getElementById('testResults').textContent);

        // Loki cannot count: `total` is the page it returned, and `exact`
        // says so. Presenting that as "5 matching records" is the same
        // falsehood in a smaller place.
        const uncounted = build(template, {
            total: 5, records: [],
            sources: [{ name: 'lab-loki', exact: false }] }, 'lab-victorialogs');
        uncounted.w.document.getElementById('testQuery').click();
        await settle();
        check('a total that is only a floor says so',
              uncounted.w.document.getElementById('testResults')
                  .textContent.includes('At least 5 matching'),
              uncounted.w.document.getElementById('testResults').textContent);

        // A store that answered only PART of the query still answers with a
        // number, and this called that "Query test successful!" with an
        // exact-looking count. The payload below is the demo's own answer to
        // the button's own request against the DEFAULT source — the one most
        // authors press — copied from /api/search.
        const shards = build(template, {
            total: 1831, partial: true, records: [],
            warnings: ['5 of 9 shards failed: Fielddata is disabled on '
                       + '[level] in [bad-logs-000001]'],
            sources: [{ name: 'elasticsearch-logs', total: 1831, exact: true,
                        failed: true }] });
        shards.w.document.getElementById('testQuery').click();
        await settle();
        const said2 = shards.w.document.getElementById('testResults');
        check('a store that answered in part is not a success',
              !said2.textContent.includes('successful')
              && said2.querySelector('.alert-warning')
              && !said2.querySelector('.alert-success'),
              said2.innerHTML);
        check('and its count is a floor, with the reason',
              said2.textContent.includes('At least 1,831 matching')
              && /shards failed/.test(said2.textContent),
              said2.textContent);

        // The reason is whatever the backend said.
        const planted = build(template, {
            total: 1, partial: true, records: [],
            warnings: ['<img src=x id=planted5>'],
            sources: [{ name: 'es', exact: true, failed: true }] });
        planted.w.document.getElementById('testQuery').click();
        await settle();
        check('a shard failure reason is text',
              !planted.w.document.getElementById('planted5'),
              planted.w.document.getElementById('testResults').innerHTML);
    }

    // The edit page's panel editor, its second script. A title went into a
    // quoted `value` attribute with only its quotes replaced, so a title
    // holding the text `&quot;` came back as a quote, and the next save
    // stored the changed title.
    {
        const text = fs.readFileSync(path.join(ROOT, 'templates', 'dashboard_edit.html'), 'utf8');
        const blocks = [...text.matchAll(/<script nonce="\{\{ csp_nonce \}\}">([\s\S]*?)<\/script>/g)]
            .map(found => found[1]);
        const title = 'Errors &quot;prod&quot; & "stage" <b>bold</b> it\'s';
        const editor = blocks[1]
            .replace('{{ aggregatable_fields | tojson }}', JSON.stringify(['service', 'level']))
            .replace('{{ panels | tojson }}', JSON.stringify(
                [{ type: 'terms', title, field: 'service', size: 10, width: 6 }]));
        const dom = new JSDOM(`<!doctype html><body><form>
          <input id="query" value="*"><div><select id="index_patterns" multiple>
          <option value="*" selected>*</option></select></div>
          <button id="testQuery"></button><div id="testResults"></div>
          <div id="panelList"></div><input type="hidden" id="panelsField">
          </form></body>`, { runScripts: 'outside-only' });
        dom.window.eval(blocks[0]);
        dom.window.eval(editor);
        const box = dom.window.document.querySelector('#panelList [data-key="title"]');
        check('a panel title comes back into its box as it was written',
              box && box.value === title, box && box.value);
        check('and brings no markup with it',
              !dom.window.document.querySelector('#panelList b'),
              dom.window.document.getElementById('panelList').innerHTML);
    }

    // The monitor rows of the same editor. A panel type the server accepts
    // and the form cannot produce is a panel nobody can add without editing
    // JSON by hand, which is the thing the panel editor exists to avoid.
    {
        const text = fs.readFileSync(path.join(ROOT, 'templates', 'dashboard_edit.html'), 'utf8');
        const blocks = [...text.matchAll(/<script nonce="\{\{ csp_nonce \}\}">([\s\S]*?)<\/script>/g)]
            .map(found => found[1]);
        const editor = blocks[1]
            .replace('{{ aggregatable_fields | tojson }}', JSON.stringify(['service']))
            .replace('{{ panels | tojson }}', JSON.stringify(
                [{ id: 'p1', type: 'terms', title: 'Top', field: 'service',
                   size: 10, width: 6 }]));
        const dom = new JSDOM(`<!doctype html><body><form>
          <input id="query" value="*"><div><select id="index_patterns" multiple>
          <option value="*" selected>*</option></select></div>
          <button id="testQuery"></button><div id="testResults"></div>
          <button type="button" data-add-panel="monitors"></button>
          <button type="button" data-add-panel="monitor_certificates"></button>
          <div id="panelList"></div><input type="hidden" id="panelsField">
          </form></body>`, { runScripts: 'outside-only' });
        const d = dom.window.document;
        dom.window.eval(blocks[0]);
        dom.window.eval(editor);

        d.querySelector('[data-add-panel="monitors"]').click();
        const rows = d.querySelectorAll('#panelList .list-group-item');
        const view = rows[1].querySelector('[data-key="view"]');
        check('the editor can add a monitor panel',
              view && JSON.parse(d.getElementById('panelsField').value)[1].type
                   === 'monitors',
              d.getElementById('panelsField').value);
        check('and it starts on status, the cheaper of the two questions',
              view && view.value === 'status', view && view.value);

        view.value = 'availability';
        view.dispatchEvent(new dom.window.Event('change'));
        d.querySelector('form').dispatchEvent(
            new dom.window.Event('submit', { cancelable: true }));
        check('and the view a person chose is what gets saved',
              JSON.parse(d.getElementById('panelsField').value)[1].view
                  === 'availability',
              d.getElementById('panelsField').value);

        d.querySelector('[data-add-panel="monitor_certificates"]').click();
        const saved = JSON.parse(d.getElementById('panelsField').value);
        check('the editor can add a certificate panel',
              saved[2] && saved[2].type === 'monitor_certificates',
              d.getElementById('panelsField').value);
        check('a monitor row says the permission it needs to draw',
              /monitors:read/.test(d.getElementById('panelList').textContent),
              d.getElementById('panelList').textContent);
    }

    console.log(failures.length ? `\n${failures.length} failure(s)`
                                : '\nall dashboard form checks passed');
    process.exit(failures.length ? 1 : 0);
})();
