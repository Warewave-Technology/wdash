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

    /** The editor script with its Jinja values filled in.
     *
     * `fields` is the standard list the server falls back to; `offered` is
     * what the DASHBOARD'S SOURCE said it can group by, which is what the
     * selects are actually built from. They are two values because they are
     * two facts: one is a constant, the other is a backend's answer, and
     * `reason` says why the select is showing the first.
     */
    function editor({ panels, fields = ['severity', 'service', 'host', 'environment'],
                      offered = null, reason = null,
                      heights = [[180, 'short'], [300, 'standard'],
                                 [450, 'tall'], [600, 'very tall']],
                      defaulted = false } = {}) {
        const text = fs.readFileSync(EDITOR, 'utf8');
        const found = text.match(/<script nonce="\{\{ csp_nonce \}\}">([\s\S]*?)<\/script>/);
        if (!found) throw new Error('no script in the editor include');
        return found[1]
            .replace('{{ aggregatable_fields | tojson }}', JSON.stringify(fields))
            .replace('{{ group_by_fields | tojson }}',
                     JSON.stringify(offered === null ? fields : offered))
            .replace('{{ group_by_reason | tojson }}', JSON.stringify(reason))
            .replace('{{ panel_heights | tojson }}', JSON.stringify(heights))
            .replace('{{ panels_are_default | tojson }}', JSON.stringify(defaulted))
            .replace('{{ panels | tojson }}', JSON.stringify(panels));
    }

    /** A page with the pieces _dashboard_editor.html provides. */
    function editorPage(options = {}) {
        const dom = new JSDOM(`<!doctype html><body><form>
          <!-- The source select lives on the form above the editor, and it
               decides what can be grouped by: it is here because the editor
               listens to it. -->
          <select id="source" name="source">
            <option value="" selected>Default (es)</option>
            <option value="loki-lab">loki-lab</option>
          </select>
          <button type="button" data-add-panel="timeseries"></button>
          <button type="button" data-add-panel="terms"></button>
          <button type="button" data-add-panel="records"></button>
          <button type="button" data-add-panel="trace_services"></button>
          <button type="button" data-add-panel="trace_list"></button>
          <button type="button" data-add-panel="monitors"></button>
          <button type="button" data-add-panel="monitor_certificates"></button>
          <!-- Not in the real menu: a stand-in for the next panel type,
               put on the page by whoever forgets to write its blank. -->
          <button type="button" data-add-panel="a_type_from_the_future"></button>
          <div id="panelList"></div>
          <div class="form-text" id="groupByNote"></div>
          <input type="hidden" id="panelsField">
          </form></body>`, { runScripts: 'outside-only' });
        const said = [];
        const asked = [];
        dom.window.alert = (message) => said.push(message);
        // The editor asks the server what the newly chosen source can group
        // by. `answers` is what it gets, in order.
        const answers = (options.answers || []).slice();
        dom.window.fetch = (url) => {
            asked.push(url);
            const next = answers.shift();
            if (next === undefined) return Promise.reject(new Error('offline'));
            return Promise.resolve({ ok: next.ok !== false,
                                     json: () => Promise.resolve(next) });
        };
        dom.window.eval(editor(options));
        return { d: dom.window.document, w: dom.window, said, asked };
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

    // The two panel types the server accepted and this form could not
    // produce. Measured before the fix: the add menu offered five types and
    // named neither, and a STORED records panel opened here was handed the
    // timeseries controls — a "Split by" select belonging to another
    // question, whose value `normalise` then dropped on save.
    {
        const { d } = editorPage({ panels: [
            { id: 'p1', type: 'terms', title: 'Top', field: 'service',
              size: 10, width: 6, height: 300 }] });

        d.querySelector('[data-add-panel="records"]').click();
        const records = rows(d)[1];
        check('the editor can add a records panel',
              stored(d)[1] && stored(d)[1].type === 'records',
              d.getElementById('panelsField').value);
        check('and it gets its own control, not the timeseries one',
              records.querySelector('[data-key="size"]')
              && !records.querySelector('[data-key="split_by"]'),
              records.innerHTML);
        check('a records row says what the panel costs to ask',
              /one more request/.test(records.textContent)
              && !/Split by/.test(records.textContent), records.textContent);

        // 25 rows, not 50: the server clamps a records panel to MAX_RECORDS,
        // and a box offering what the store will silently halve is a lie the
        // author finds by counting rows.
        check('and the row count it offers is the one the server keeps',
              records.querySelector('[data-key="size"]').max === '25',
              records.querySelector('[data-key="size"]').outerHTML);

        d.querySelector('[data-add-panel="trace_list"]').click();
        const list = rows(d)[2];
        check('the editor can add a trace list',
              stored(d)[2] && stored(d)[2].type === 'trace_list',
              d.getElementById('panelsField').value);
        check('with a service box, a view and a row count',
              ['service', 'view', 'size'].every(
                  k => list.querySelector(`[data-key="${k}"]`))
              && !list.querySelector('[data-key="split_by"]'), list.innerHTML);
        check('the view starts on the slowest and offers only what the save accepts',
              [...list.querySelector('[data-key="view"]').options]
                  .map(o => o.value).join(',') === 'slowest,recent,errors'
              && list.querySelector('[data-key="view"]').value === 'slowest',
              list.querySelector('[data-key="view"]').innerHTML);
    }

    // `errors` is in two of the option lists and is not the same question in
    // both: on a trace list it is a VIEW — the traces that failed and no
    // others — and on a trace_services panel it is an ORDERING over every
    // service the window holds. panels.py says so where TRACE_LIST_VIEWS is
    // defined ("'errors' is not an ordering"). One label table keyed by the
    // bare value made the Sort by select read "errors only", which tells the
    // author a panel that ranks all services by error count shows only errors.
    {
        const { d } = editorPage({ panels: [
            { id: 'p1', type: 'trace_services', title: 'S', sort: 'spans',
              size: 10, width: 6, height: 300 },
            { id: 'p2', type: 'trace_list', title: 'T', service: 'pay',
              view: 'slowest', size: 5, width: 6, height: 300 }] });
        const labels = (index, key) => [...rows(d)[index]
            .querySelector(`[data-key="${key}"]`).options]
            .map(o => `${o.value}=${o.textContent.trim()}`).join(' ');
        check('ordering services by errors is an ordering, not a filter',
              labels(0, 'sort')
              === 'spans=spans errors=errors error_rate=error rate',
              labels(0, 'sort'));
        check('and a trace list showing errors shows only those',
              labels(1, 'view')
              === 'slowest=the slowest recent=the newest errors=errors only',
              labels(1, 'view'));
    }

    // A number box can be emptied, and `parseInt('')` is NaN — which
    // JSON.stringify writes as `null`, and `normalise` reading `int(None)`
    // refuses the panel for the WHOLE board. The refusal is not confined to
    // that panel either: `_resubmitted` cannot re-render a list that fails to
    // validate, so clearing this box and pressing Save threw away every other
    // edit on the page, with only "size must be a number" said about it.
    {
        const { d } = editorPage({ panels: [
            { id: 'p1', type: 'terms', title: 'Top', field: 'service',
              size: 10, width: 6, height: 300 }] });
        d.querySelector('[data-add-panel="records"]').click();

        const title = rows(d)[0].querySelector('[data-key="title"]');
        title.value = 'AN EDIT I MADE';
        title.dispatchEvent(new d.defaultView.Event('change'));

        const size = rows(d)[1].querySelector('[data-key="size"]');
        size.value = '';
        size.dispatchEvent(new d.defaultView.Event('change'));
        check('an emptied row count is not posted as no number at all',
              stored(d)[1].size === 10, d.getElementById('panelsField').value);
        check('and the box shows what will be saved rather than staying empty',
              size.value === '10', size.value);
        check('so the edit made beside it is still there to save',
              stored(d)[0].title === 'AN EDIT I MADE',
              d.getElementById('panelsField').value);

        size.value = '3';
        size.dispatchEvent(new d.defaultView.Event('change'));
        check('and a row count that IS a number is still the author’s',
              stored(d)[1].size === 3, d.getElementById('panelsField').value);
    }

    // A trace list with no service is a save the server refuses — and a
    // refusal re-renders the form from the STORED list, so the refused panel
    // and every edit made beside it disappear. The form has to say so first.
    {
        const { d, said } = editorPage({ panels: [
            { id: 'p1', type: 'terms', title: 'Top', field: 'service',
              size: 10, width: 6, height: 300 }] });
        d.querySelector('[data-add-panel="trace_list"]').click();

        check('a trace list with no service says so on the row',
              rows(d)[1].querySelector('[data-needs-service]')
              && /needs a service/.test(rows(d)[1].textContent),
              rows(d)[1].textContent);

        const submit = new d.defaultView.Event('submit', { cancelable: true });
        d.querySelector('form').dispatchEvent(submit);
        check('and submitting is stopped, with the reason and the panel named',
              submit.defaultPrevented && said.length === 1
              && /needs a service/.test(said[0])
              && /Traces for one service/.test(said[0]), JSON.stringify(said));

        const service = rows(d)[1].querySelector('[data-key="service"]');
        service.value = 'payment-service';
        service.dispatchEvent(new d.defaultView.Event('change'));
        check('naming a service takes the warning off the row',
              !rows(d)[1].querySelector('[data-needs-service]'),
              rows(d)[1].textContent);

        const second = new d.defaultView.Event('submit', { cancelable: true });
        d.querySelector('form').dispatchEvent(second);
        check('and then the form submits, with the service in the field',
              !second.defaultPrevented && stored(d)[1].service === 'payment-service'
              && said.length === 1, d.getElementById('panelsField').value);
    }

    // The service is free text, and it goes into a quoted attribute.
    {
        const service = 'pay "prod" & <b>bold</b>';
        const { d } = editorPage({ panels: [
            { id: 'p1', type: 'trace_list', title: 'T', service,
              view: 'errors', size: 5, width: 6, height: 300 }] });
        const box = d.querySelector('[data-key="service"]');
        check('a stored service comes back into its box as it was written',
              box && box.value === service, box && box.value);
        check('and brings no markup with it',
              !d.querySelector('#panelList b'),
              d.getElementById('panelList').innerHTML);
        check('a stored view is the one selected',
              d.querySelector('[data-key="view"]').value === 'errors',
              d.querySelector('[data-key="view"]').value);
    }

    // The fall-through. The chain ended in the timeseries controls, so a type
    // it did not name was handed a "Split by" select and a caption reading
    // the raw type name. Nothing rather than somebody else's question.
    {
        const { d } = editorPage({ panels: [
            { id: 'p1', type: 'a_type_from_the_future', title: 'Mystery',
              width: 6, height: 300 }] });
        const row = rows(d)[0];
        check('a panel type the editor does not know is offered no controls',
              !row.querySelector('[data-key="split_by"]')
              && !row.querySelector('[data-key="field"]')
              && !row.querySelector('[data-key="view"]'), row.innerHTML);
        check('and its caption says nothing rather than the type name',
              !/a_type_from_the_future/.test(row.textContent), row.textContent);
        check('while the controls every panel has still work',
              ['title', 'width', 'height'].every(
                  k => row.querySelector(`[data-key="${k}"]`)), row.innerHTML);
    }

    // A button naming a type with no blank pushed `{...undefined}` — a panel
    // with no type, which the save refuses for the whole board.
    {
        const { d } = editorPage({ panels: [
            { id: 'p1', type: 'terms', title: 'Top', field: 'service',
              size: 10, width: 6, height: 300 }] });
        for (const type of ['timeseries', 'terms', 'records', 'trace_services',
                            'trace_list', 'monitors', 'monitor_certificates']) {
            d.querySelector(`[data-add-panel="${type}"]`).click();
        }
        check('every button in the menu adds a panel of its own type',
              stored(d).length === 8
              && stored(d).slice(1).map(p => p.type).join(',') ===
                 'timeseries,terms,records,trace_services,trace_list,'
                 + 'monitors,monitor_certificates',
              d.getElementById('panelsField').value);
        check('and no panel arrives without a type',
              stored(d).every(p => p.type), d.getElementById('panelsField').value);

        // The button nobody wrote a blank for. It used to push
        // `{...undefined}` — a panel with no type, which the save refuses for
        // the WHOLE board with "Unknown panel type: (none)".
        const before = d.getElementById('panelsField').value;
        d.querySelector('[data-add-panel="a_type_from_the_future"]').click();
        check('a button with no blank behind it adds nothing at all',
              d.getElementById('panelsField').value === before
              && stored(d).length === 8, d.getElementById('panelsField').value);
    }

    // A panel arriving without one of its own keys — a list hand-edited into
    // the record, or a key a future `normalise` stops writing. The select has
    // to land on a value the save accepts rather than on nothing.
    {
        const { d } = editorPage({ panels: [
            { id: 'p1', type: 'trace_list', title: 'T', service: 'payments',
              width: 6, height: 300 }] });
        const view = d.querySelector('[data-key="view"]');
        // Marked, not merely displayed: a select whose options carry no
        // `selected` shows its FIRST option whatever the fallback was, so a
        // default naming a value the save refuses looks right on screen.
        check('a trace list with no view stored starts on the slowest',
              view.value === 'slowest'
              && (view.querySelector('option[selected]') || {}).value === 'slowest'
              && [...view.options].map(o => o.value).join(',')
                 === 'slowest,recent,errors', view.innerHTML);
        const { d: plain } = editorPage({ panels: [
            { id: 'p1', type: 'records', title: 'R', width: 12,
              height: 450 }] });
        check('and a records panel with no size shows the rows it will get',
              plain.querySelector('[data-key="size"]').value === '10',
              plain.querySelector('[data-key="size"]').outerHTML);
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

    // ---------------------------------------------------------------
    // What the Group by / Split by selects offer.
    //
    // Four names, hardcoded, to every backend. Two of them — `host` and
    // `environment` — are answered by the lab's Loki with nothing at all,
    // and six fields its Elasticsearch index maps and can group by
    // (`http_status`, `user_id`, `correlation_id`, `request_id`,
    // `duration_ms`, `trace_id`) could not be asked for by any board.
    // ---------------------------------------------------------------
    {
        const groupBy = (d) => Array.from(
            d.querySelectorAll('#panelList [data-key="field"] option'),
            o => o.value);

        const { d } = editorPage({
            panels: [{ id: 'p', type: 'terms', title: 'Top', field: 'service',
                       size: 10, width: 6, height: 300 }],
            offered: ['severity', 'service', 'http_status', 'user_id'] });
        check('the group-by select offers what the SOURCE can group by',
              groupBy(d).join() === 'severity,service,http_status,user_id',
              groupBy(d).join());
        check('and the note says whose list it is',
              /4 fields/.test(d.getElementById('groupByNote').textContent),
              d.getElementById('groupByNote').textContent);

        // Advisory, not a fence: a stored panel keeps its own field even
        // when the source stops listing it. Dropping it would not refuse the
        // panel — the select would simply be showing a DIFFERENT field, and
        // the next change to the row would save that one instead.
        const stale = editorPage({
            panels: [{ id: 'p', type: 'terms', title: 'Top',
                       field: 'http_status', size: 10, width: 6, height: 300 }],
            offered: ['severity', 'service'] });
        const select = stale.d.querySelector('#panelList [data-key="field"]');
        check('a stored field the source no longer lists stays selected',
              select.value === 'http_status', select.value);
        check('and is marked as one this source does not offer',
              /not offered by this source/.test(select.innerHTML),
              select.innerHTML);

        // The failure that must not look like emptiness: a source that could
        // not be asked leaves a usable select AND says why.
        const down = editorPage({
            panels: [{ id: 'p', type: 'terms', title: 'Top', field: 'service',
                       size: 10, width: 6, height: 300 }],
            fields: ['severity', 'service', 'host', 'environment'],
            offered: ['severity', 'service', 'host', 'environment'],
            reason: "The fields of 'es' could not be read (connection "
                    + 'refused); these are the standard ones.' });
        check('a discovery that failed still offers the standard fields',
              groupBy(down.d).join() === 'severity,service,host,environment',
              groupBy(down.d).join());
        check('and says so rather than showing them as the source’s own',
              /could not be read/.test(
                  down.d.getElementById('groupByNote').textContent)
              && down.d.getElementById('groupByNote')
                     .classList.contains('text-warning'),
              down.d.getElementById('groupByNote').outerHTML);

        // Changing the source changes what can be grouped by, and the select
        // has to follow: a board moved from Elasticsearch to Loki keeps
        // offering four names Loki answers two of.
        const moved = editorPage({
            panels: [{ id: 'p', type: 'terms', title: 'Top', field: 'service',
                       size: 10, width: 6, height: 300 }],
            offered: ['severity', 'service', 'http_status'],
            answers: [{ source: 'loki-lab', fields: ['service', 'severity'],
                        reason: null }] });
        moved.d.getElementById('source').value = 'loki-lab';
        moved.d.getElementById('source').dispatchEvent(
            new moved.w.Event('change'));
        await settle();
        check('choosing another source asks that source what it can group by',
              moved.asked.length === 1
              && moved.asked[0].includes('source=loki-lab'), moved.asked);
        check('and the select is rebuilt from its answer',
              groupBy(moved.d).join() === 'service,severity',
              groupBy(moved.d).join());
        check('while the panel keeps the field it had',
              stored(moved.d)[0].field === 'service',
              moved.d.getElementById('panelsField').value);

        // And an ask that fails leaves what is on screen rather than
        // emptying the select.
        const offline = editorPage({
            panels: [{ id: 'p', type: 'terms', title: 'Top', field: 'service',
                       size: 10, width: 6, height: 300 }],
            offered: ['severity', 'service', 'http_status'], answers: [] });
        offline.d.getElementById('source').value = 'loki-lab';
        offline.d.getElementById('source').dispatchEvent(
            new offline.w.Event('change'));
        await settle();
        check('a failed ask leaves the select it could not replace',
              groupBy(offline.d).join() === 'severity,service,http_status',
              groupBy(offline.d).join());
    }

    console.log(failures.length ? `\n${failures.length} failure(s)`
                                : '\nall dashboard form checks passed');
    process.exit(failures.length ? 1 : 0);
})();
