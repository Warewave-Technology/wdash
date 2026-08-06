/**
 * The role editor's boundary fields.
 *
 * These stay free text, and that is a decision. Containers rotate: a role
 * granted `app-logs-000001` by name silently loses access the day `-000002`
 * appears, which is a worse failure than a typo and a much quieter one.
 * Patterns are what survive rotation, so they stay.
 *
 * The danger was never typing — it was typing blind. What these checks hold is
 * that you cannot any more:
 *
 *   * a pattern matching nothing says so, which is what a typo looks like
 *   * a pattern matching EVERYTHING says so, which is the dangerous direction
 *     nothing used to flag: `*` where `app-*` was meant saves cleanly and
 *     grants the whole cluster
 *   * what exists is one click away, offered as a rotation-proof pattern first
 *
 * The matching itself happens on the server. Reimplementing the pattern
 * language here would give the product two of them under one name — a bug this
 * codebase has already had once.
 *
 * Run: npm test
 */

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const ROOT = path.join(__dirname, '..');
const failures = [];

function check(name, condition, detail) {
    // A function is always truthy. Passing one here — the shape the other
    // smoke file uses — printed "ok" for four tests that never ran a line of
    // the code they claimed to cover, and seven mutations sailed through.
    if (typeof condition === 'function') {
        throw new Error(
            `check("${name}") was given a function. This file's check takes a ` +
            `BOOLEAN; a callback is silently truthy and the test passes ` +
            `without running.`);
    }
    if (condition) {
        console.log(`  ok    ${name}`);
    } else {
        failures.push(name);
        console.log(`  FAIL  ${name}${detail ? '\n        ' + detail : ''}`);
    }
}

function build() {
    const dom = new JSDOM(`<!doctype html><body>
      <div id="rolePermissions">
        <input type="checkbox" name="permissions" value="logs:read">
      </div>
      <textarea class="boundary-field" id="roleContainers" data-kind="logs"></textarea>
      <div class="boundary-verdict" data-for="roleContainers"></div>
      <textarea class="boundary-field" id="roleTraceContainers" data-kind="traces"></textarea>
      <div class="boundary-verdict" data-for="roleTraceContainers"></div>
      <textarea class="boundary-field" id="roleServices" data-kind="services"></textarea>
      <div class="boundary-verdict" data-for="roleServices"></div>
      <input id="roleName"><input id="roleDescription"><textarea id="roleGroups"></textarea>
      <input id="roleMode"><div id="rolePreview"></div><h5 id="roleModalTitle"></h5>
      <button id="addRoleBtn"></button>
      <button class="edit-role" data-role='{"name":"viewer","permissions":["logs:read"],"containers":["app-*"],"trace_containers":[],"services":null,"groups":[]}'></button>
      <button class="pick-target" data-kind="logs" data-target="roleContainers"></button>
      <div class="modal fade" id="targetPicker"></div>
      <div id="targetPickerBody"></div><h5 id="targetPickerTitle"></h5>
      <div class="modal fade show" id="roleModal"></div>

      <select id="sourceKind"><option value="elasticsearch">es</option></select>
      <div class="form-check" data-signal="logs">
        <input type="checkbox" name="signals" value="logs" id="sourceSignalLogs">
      </div>
      <div class="form-check" data-signal="traces">
        <input type="checkbox" name="signals" value="traces" id="sourceSignalTraces">
      </div>
      <input type="hidden" name="signals" id="sourceSignalFixed" disabled value="">
      <div data-kind="elasticsearch" data-needs="logs" id="logPatternField"></div>
      <div data-kind="elasticsearch" data-needs="traces" id="tracePatternField"></div>
      <script type="application/json" id="sourceSignals">
        {"elasticsearch": ["logs", "traces"], "loki": ["logs"],
         "jaeger": ["traces"], "tempo": ["traces"],
         "victorialogs": ["logs"]}
      </script>
      <form></form></body>`,
      { runScripts: 'outside-only', url: 'http://localhost/admin/config' });

    const w = dom.window;
    global.window = w;
    global.document = w.document;
    w.bootstrap = { Modal: class { constructor() {} show() {}
                                   static getInstance() { return null; } } };

    const calls = [];
    w.fetch = (url, options) => {
        calls.push(url);
        if (url.includes('/available')) {
            return Promise.resolve({ json: () => Promise.resolve({
                logs: [{ source: 'es',
                         containers: ['app-logs-000001', 'infra-logs-000001'] }],
                traces: [], services: ['api-gateway'] }) });
        }
        const containers = JSON.parse(options.body).containers || [];
        const matched = containers.includes('*') ? 2
                      : containers.includes('app-*') ? 1 : 0;
        return Promise.resolve({ json: () => Promise.resolve({
            logs: [{ source: 'es', count: matched, total: 2,
                     containers: matched ? ['app-logs-000001'] : [] }],
            traces: [], services: 'every service', permissions: [], warnings: [],
            reaches_nothing: matched === 0,
            reaches_everything: { logs: matched === 2, traces: false,
                                  services: true } }) });
    };

    w.eval(fs.readFileSync(path.join(ROOT, 'static/js/config.js'), 'utf8'));
    return { w, calls };
}

const settle = () => new Promise(resolve => setTimeout(resolve, 450));
const verdict = (w, id) => w.document
    .querySelector(`.boundary-verdict[data-for="${id}"]`).textContent.trim();

function type(w, id, value) {
    const field = w.document.getElementById(id);
    field.value = value;
    field.dispatchEvent(new w.Event('input'));
}

(async () => {
    console.log('role editor');

    const { w, calls } = build();

    // `previewTimer` is declared with `let` after `fillRole` in the file;
    // opening a role must not hit its temporal dead zone.
    let opened = true;
    try {
        w.document.querySelector('.edit-role').dispatchEvent(new w.Event('click'));
    } catch (error) {
        opened = false;
        check('opening a role does not throw', false, error.message);
    }
    if (opened) check('opening a role does not throw', true);

    await settle();
    check('an existing role shows its verdict without being touched',
          verdict(w, 'roleContainers').includes('1 of 2'),
          verdict(w, 'roleContainers'));

    type(w, 'roleContainers', 'applicaiton-*');
    await settle();
    check('a pattern matching nothing says so',
          /matches nothing/i.test(verdict(w, 'roleContainers')),
          verdict(w, 'roleContainers'));

    type(w, 'roleContainers', '*');
    await settle();
    check('a pattern matching everything says so',
          /everything/i.test(verdict(w, 'roleContainers')),
          verdict(w, 'roleContainers'));

    type(w, 'roleContainers', 'app-*');
    await settle();
    check('a working pattern shows what it reaches',
          verdict(w, 'roleContainers').includes('app-logs-000001'),
          verdict(w, 'roleContainers'));

    check('a blank services field reads as unrestricted',
          /every service/i.test(verdict(w, 'roleServices')),
          verdict(w, 'roleServices'));

    const before = calls.length;
    type(w, 'roleContainers', 'a');
    type(w, 'roleContainers', 'ap');
    type(w, 'roleContainers', 'app');
    await settle();
    check('typing is debounced into one request',
          calls.length - before === 1, `${calls.length - before} requests`);

    w.document.querySelector('.pick-target').dispatchEvent(new w.Event('click'));
    await new Promise(resolve => setTimeout(resolve, 150));
    const picker = w.document.getElementById('targetPickerBody').innerHTML;
    check('the picker offers a rotation-proof pattern first',
          picker.includes('app-logs*'));
    check('and an exact name as the deliberate alternative',
          picker.includes('>exact<'));

    // --- the picker opens on top of the editor, not behind it ---

    const editor = w.document.getElementById('roleModal');
    const pickerModal = w.document.getElementById('targetPicker');

    // Bootstrap fires these; the harness stands in for it. The backdrop is
    // appended between `show` and `shown`, which is why the order matters.
    pickerModal.dispatchEvent(new w.Event('show.bs.modal'));
    const backdrop = w.document.createElement('div');
    backdrop.className = 'modal-backdrop';
    w.document.body.appendChild(backdrop);
    pickerModal.classList.add('show');
    pickerModal.dispatchEvent(new w.Event('shown.bs.modal'));

    // Both modals carry Bootstrap's 1055 by default, so equal is not enough:
    // with equal z-index the one declared first in the document loses, and
    // the picker is declared first.
    const above = Number(pickerModal.style.zIndex);
    check('the picker is raised above the editor it opened from',
          above > 1055, `z-index is ${pickerModal.style.zIndex || 'unset'}`);
    check('its backdrop dims the editor without hiding the picker',
          Number(backdrop.style.zIndex) > 1055
          && Number(backdrop.style.zIndex) < above,
          `backdrop ${backdrop.style.zIndex || 'unset'} vs picker ${above}`);

    pickerModal.classList.remove('show');
    backdrop.remove();
    w.document.body.classList.remove('modal-open');
    pickerModal.dispatchEvent(new w.Event('hidden.bs.modal'));
    check('closing the picker leaves the editor still behaving as a modal',
          w.document.body.classList.contains('modal-open'),
          'the page scrolls behind the open editor');

    // Opened on its own it must not invent a stacking level, or every later
    // modal has to out-climb a number that came from nowhere.
    editor.classList.remove('show');
    pickerModal.style.zIndex = '';
    pickerModal.dispatchEvent(new w.Event('show.bs.modal'));
    check('a picker opened on its own keeps the default depth',
          pickerModal.style.zIndex === '',
          `z-index is ${pickerModal.style.zIndex}`);

    // --- what a source type serves ---

    const signalState = (w) => {
        const rows = {};
        w.document.querySelectorAll('[data-signal]').forEach(element => {
            const box = element.querySelector('input');
            rows[element.dataset.signal] = {
                shown: !element.classList.contains('d-none'),
                checked: box.checked,
                disabled: box.disabled,
            };
        });
        rows.carrier = w.document.getElementById('sourceSignalFixed');
        return rows;
    };

    const both = build().w;
    both.applyKind('elasticsearch');
    const es = signalState(both);
    check('a type serving both offers both',
          es.logs.shown && es.traces.shown,
          `logs=${es.logs.shown} traces=${es.traces.shown}`);
    check('a real choice is not presented as fixed',
          !es.logs.disabled && !es.traces.disabled);
    check('the hidden carrier stays out of the way when there is a choice',
          es.carrier.disabled);

    // An empty area under a label reads as a control that failed to render,
    // not as a type with no choice to make.
    const one = build().w;
    one.applyKind('loki');
    const loki = signalState(one);
    check('a type serving one shows that one rather than nothing',
          loki.logs.shown && loki.logs.checked,
          `shown=${loki.logs.shown} checked=${loki.logs.checked}`);
    check('the fixed signal is not editable', loki.logs.disabled);
    check('a signal the type cannot serve is not offered', !loki.traces.shown);

    // A disabled checkbox submits nothing. Without the hidden carrier the save
    // fails with "a source has to serve at least one signal", about a form the
    // person cannot argue with.
    const fixed = build().w;
    fixed.applyKind('jaeger');
    const carrier = fixed.document.getElementById('sourceSignalFixed');
    check('the fixed signal still reaches the server',
          !carrier.disabled && carrier.value === 'traces',
          `disabled=${carrier.disabled} value=${carrier.value}`);
    check('switching to a single-signal type clears the other box',
          !fixed.document.getElementById('sourceSignalLogs').checked);

    // `fillSource` ticks the boxes before applyKind runs, so the fixture has
    // to as well — otherwise nothing is ticked, every per-signal field is
    // hidden, and the test asserts against a form nobody ever sees.
    const fields = build().w;
    fields.document.getElementById('sourceSignalLogs').checked = true;
    fields.document.getElementById('sourceSignalTraces').checked = true;
    fields.applyKind('elasticsearch');
    fields.document.getElementById('sourceSignalTraces').checked = false;
    fields.applySignals();
    check('a field for a ticked signal stays',
          !fields.document.getElementById('logPatternField')
                 .classList.contains('d-none'));
    check('a field for an unticked signal goes',
          fields.document.getElementById('tracePatternField')
                .classList.contains('d-none'));

    console.log(failures.length ? `\n${failures.length} failure(s)`
                                : '\nall role editor checks passed');
    process.exit(failures.length ? 1 : 0);
})();
