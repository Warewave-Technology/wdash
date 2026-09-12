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
 * The second half is the PANEL EDITOR, which now lives in one include that
 * both forms pull in. It had two checks, both about a title round-tripping;
 * add, move, remove, the width select, the at-least-one-panel guard and the
 * new height had none, and that file is where every panel control lands.
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

    // ---------------------------------------------------------------
    // The panel editor.
    //
    // One file now, included by BOTH forms — it used to be the second
    // script block of dashboard_edit.html, so the create form had no panel
    // list at all and every dashboard was born as the same three panels.
    // Read from the include itself, so there is no copy here to drift.
    //
    // Everything below the first two checks was missing: nothing exercised
    // add, move, remove, the width select, the at-least-one-panel guard or
    // the height, and that file is where every new panel control lands.
    // ---------------------------------------------------------------
    const EDITOR = path.join(ROOT, 'templates', '_dashboard_editor_script.html');

    /** The editor script with its Jinja values filled in. */
    function editor({ panels, fields = ['service', 'level'],
                      heights = [[180, 'short'], [300, 'standard'],
                                 [450, 'tall'], [600, 'very tall']],
                      defaulted = false } = {}) {
        const text = fs.readFileSync(EDITOR, 'utf8');
        const found = text.match(/<script nonce="\{\{ csp_nonce \}\}">([\s\S]*?)<\/script>/);
        if (!found) throw new Error('no script in the editor include');
        return found[1]
            .replace('{{ aggregatable_fields | tojson }}', JSON.stringify(fields))
            .replace('{{ panel_heights | tojson }}', JSON.stringify(heights))
            .replace('{{ panels_are_default | tojson }}', JSON.stringify(defaulted))
            .replace('{{ panels | tojson }}', JSON.stringify(panels));
    }

    /** A page with the pieces _dashboard_editor.html provides. */
    function editorPage(options) {
        const dom = new JSDOM(`<!doctype html><body><form>
          <button type="button" data-add-panel="timeseries"></button>
          <button type="button" data-add-panel="terms"></button>
          <button type="button" data-add-panel="trace_services"></button>
          <button type="button" data-add-panel="monitors"></button>
          <button type="button" data-add-panel="monitor_certificates"></button>
          <div id="panelList"></div><input type="hidden" id="panelsField">
          </form></body>`, { runScripts: 'outside-only' });
        const said = [];
        dom.window.alert = (message) => said.push(message);
        dom.window.eval(editor(options));
        return { d: dom.window.document, w: dom.window, said };
    }

    const stored = (d) => JSON.parse(d.getElementById('panelsField').value || 'null');
    const rows = (d) => d.querySelectorAll('#panelList .list-group-item');

    // Both forms must actually pull the one copy in, or "shared" is a claim
    // about a file nobody includes.
    {
        for (const template of ['dashboard_create.html', 'dashboard_edit.html']) {
            const text = fs.readFileSync(
                path.join(ROOT, 'templates', template), 'utf8');
            check(`${template} includes the panel editor`,
                  text.includes('{% include "_dashboard_editor_script.html" %}')
                  && text.includes('{% include "_dashboard_editor.html" %}'),
                  template);
        }
    }

    // A title went into a quoted `value` attribute with only its quotes
    // replaced, so a title holding the text `&quot;` came back as a quote,
    // and the next save stored the changed title.
    {
        const title = 'Errors &quot;prod&quot; & "stage" <b>bold</b> it\'s';
        const { d } = editorPage({ panels: [
            { type: 'terms', title, field: 'service', size: 10, width: 6,
              height: 300 }] });
        const box = d.querySelector('#panelList [data-key="title"]');
        check('a panel title comes back into its box as it was written',
              box && box.value === title, box && box.value);
        check('and brings no markup with it',
              !d.querySelector('#panelList b'),
              d.getElementById('panelList').innerHTML);
    }

    // Adding, moving and removing: the three things the editor is for, and
    // the three nothing had ever run.
    {
        const { d, said } = editorPage({ panels: [
            { id: 'p1', type: 'terms', title: 'First', field: 'service',
              size: 10, width: 6, height: 300 }] });

        d.querySelector('[data-add-panel="timeseries"]').click();
        check('adding a panel appends it to the list and to the field',
              rows(d).length === 2 && stored(d).length === 2
              && stored(d)[1].type === 'timeseries', d.getElementById('panelsField').value);

        d.querySelectorAll('[data-move="-1"]')[1].click();
        check('moving a panel up swaps it with the one above',
              stored(d)[0].type === 'timeseries' && stored(d)[1].id === 'p1',
              d.getElementById('panelsField').value);

        check('the first row cannot be moved up and the last cannot be moved down',
              rows(d)[0].querySelector('[data-move="-1"]').disabled
              && rows(d)[1].querySelector('[data-move="1"]').disabled
              && !rows(d)[0].querySelector('[data-move="1"]').disabled,
              d.getElementById('panelList').innerHTML);

        // The ends are guarded twice: the button is disabled, and the
        // handler refuses an index outside the list. The second is what
        // stands between a stray click and `panels[2]` on a list of two, so
        // it is dispatched rather than pressed — `.click()` on a disabled
        // button fires nothing and measures nothing.
        const before = d.getElementById('panelsField').value;
        rows(d)[1].querySelector('[data-move="1"]')
            .dispatchEvent(new d.defaultView.Event('click'));
        rows(d)[0].querySelector('[data-move="-1"]')
            .dispatchEvent(new d.defaultView.Event('click'));
        check('a move past either end changes nothing',
              d.getElementById('panelsField').value === before
              && stored(d).length === 2,
              d.getElementById('panelsField').value);

        d.querySelectorAll('[data-remove]')[0].click();
        check('removing a panel takes it out of the field too',
              rows(d).length === 1 && stored(d).length === 1
              && stored(d)[0].id === 'p1', d.getElementById('panelsField').value);

        d.querySelector('[data-remove]').click();
        check('the last panel cannot be removed, and the reason is said',
              rows(d).length === 1 && said.length === 1
              && /at least one panel/.test(said[0]), JSON.stringify(said));
    }

    // Width and height. The server clamps both; what is measured here is
    // that what a person chose is what gets sent, which is where a control
    // wired to the wrong key goes unnoticed.
    {
        const { d } = editorPage({ panels: [
            { id: 'p1', type: 'terms', title: 'T', field: 'service', size: 10,
              width: 6, height: 300 }] });

        const width = d.querySelector('[data-key="width"]');
        const height = d.querySelector('[data-key="height"]');
        check('the width and height selects start on the panel’s own values',
              width.value === '6' && height.value === '300',
              `${width.value} / ${height.value}`);

        height.value = '450';
        height.dispatchEvent(new d.defaultView.Event('change'));
        width.value = '12';
        width.dispatchEvent(new d.defaultView.Event('change'));
        d.querySelector('form').dispatchEvent(
            new d.defaultView.Event('submit', { cancelable: true }));
        check('a chosen height is saved as a number, not as text',
              stored(d)[0].height === 450 && stored(d)[0].width === 12,
              d.getElementById('panelsField').value);
    }

    // A panel type the server accepts and the form cannot produce is a panel
    // nobody can add without editing JSON by hand.
    {
        const { d } = editorPage({ fields: ['service'], panels: [
            { id: 'p1', type: 'terms', title: 'Top', field: 'service',
              size: 10, width: 6, height: 300 }] });

        d.querySelector('[data-add-panel="monitors"]').click();
        const view = rows(d)[1].querySelector('[data-key="view"]');
        check('the editor can add a monitor panel',
              view && stored(d)[1].type === 'monitors',
              d.getElementById('panelsField').value);
        check('and it starts on status, the cheaper of the two questions',
              view && view.value === 'status', view && view.value);

        view.value = 'availability';
        view.dispatchEvent(new d.defaultView.Event('change'));
        d.querySelector('form').dispatchEvent(
            new d.defaultView.Event('submit', { cancelable: true }));
        check('and the view a person chose is what gets saved',
              stored(d)[1].view === 'availability',
              d.getElementById('panelsField').value);

        d.querySelector('[data-add-panel="monitor_certificates"]').click();
        check('the editor can add a certificate panel',
              stored(d)[2] && stored(d)[2].type === 'monitor_certificates',
              d.getElementById('panelsField').value);
        check('a monitor row says the permission it needs to draw',
              /monitors:read/.test(d.getElementById('panelList').textContent),
              d.getElementById('panelList').textContent);
    }

    // The create form renders the DEFAULT panel set, which it must not then
    // write into the record: the server reads an absent `panels` as "follow
    // the defaults", and a form that always posted its list would freeze
    // today's defaults into every dashboard ever created.
    {
        const defaults = [
            { id: 'default-volume', type: 'timeseries', title: 'Volume by Severity',
              split_by: 'severity', width: 12, height: 300 },
            { id: 'default-levels', type: 'terms', title: 'Log Levels',
              field: 'severity', size: 10, width: 4, height: 300 }];

        const untouched = editorPage({ panels: defaults, defaulted: true });
        untouched.d.querySelector('form').dispatchEvent(
            new untouched.d.defaultView.Event('submit', { cancelable: true }));
        check('an untouched default set is posted as absent, not as itself',
              untouched.d.getElementById('panelsField').value === '',
              untouched.d.getElementById('panelsField').value);

        const touched = editorPage({ panels: defaults, defaulted: true });
        touched.d.querySelector('[data-add-panel="terms"]').click();
        check('and the moment it is changed the whole list is posted',
              stored(touched.d) && stored(touched.d).length === 3,
              touched.d.getElementById('panelsField').value);

        // The edit form of a board somebody HAS customised always posts,
        // even before anything is touched — there is nothing to fall back to.
        const chosen = editorPage({ panels: defaults, defaulted: false });
        check('a list somebody chose is posted whether or not it is touched',
              stored(chosen.d) && stored(chosen.d).length === 2,
              chosen.d.getElementById('panelsField').value);
    }

    console.log(failures.length ? `\n${failures.length} failure(s)`
                                : '\nall dashboard form checks passed');
    process.exit(failures.length ? 1 : 0);
})();
