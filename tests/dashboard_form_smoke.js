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

/** The form, with the search API answering `answer` (or failing). */
function build(template, answer) {
    const dom = new JSDOM(`<!doctype html><body>
      <input id="query" value="level:ERROR">
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

    console.log(failures.length ? `\n${failures.length} failure(s)`
                                : '\nall dashboard form checks passed');
    process.exit(failures.length ? 1 : 0);
})();
