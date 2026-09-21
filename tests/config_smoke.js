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
      <button class="pick-target" id="pickServices" data-kind="services"
              data-target="roleServices"></button>
      <div class="modal fade" id="targetPicker"></div>
      <div id="targetPickerBody"></div><h5 id="targetPickerTitle"></h5>
      <div class="modal fade show" id="roleModal"></div>

      <select id="sourceKind"><option value="elasticsearch">es</option></select>
      <input id="sourceId"><input id="sourceUrl"><input id="sourceUsername">
      <input id="sourcePassword"><input type="checkbox" id="sourceVerify">
      <button id="testSourceBtn"></button><div id="sourceTestResult"></div>

      <!-- The source editor, as the page renders it. Every field fillSource
           writes to, because a field it forgets keeps whatever the DOM last
           held and the save writes that. -->
      <h5 id="sourceModalTitle"></h5>
      <button id="addSourceBtn"></button>
      <input id="sourceName"><input id="sourceLogPatterns">
      <input id="sourceTracePatterns"><input id="sourceMonitorPatterns">
      <input id="sourceExcludes"><input id="sourceTenant">
      <input id="sourceStreamLabel"><input id="sourceStreamField">
      <input type="checkbox" id="sourceEnabled">
      <div id="sourcePasswordHint"></div>
      <button class="edit-source" data-source='{"id":"1","name":"cluster","kind":"elasticsearch","enabled":true,"has_secret":true,"signals":["logs","monitors"],"config":{"url":"http://cluster:9200","logs":{"index_patterns":["app-*"]},"monitors":{"index_patterns":["synthetics-prod-*"]}}}'></button>
      <button class="edit-source" data-source='{"id":"2","name":"other","kind":"elasticsearch","enabled":true,"has_secret":false,"signals":["logs","monitors"],"config":{"url":"http://other:9200","logs":{"index_patterns":["infra-*"]},"monitors":{"index_patterns":["uptime-*"]}}}'></button>
      <form id="deleteForm" data-confirm="Delete lab-&lt;b&gt;es&lt;/b&gt;?"></form>
      <div class="form-check" data-signal="logs">
        <input type="checkbox" name="signals" value="logs" id="sourceSignalLogs">
      </div>
      <div class="form-check" data-signal="traces">
        <input type="checkbox" name="signals" value="traces" id="sourceSignalTraces">
      </div>
      <div class="form-check" data-signal="monitors">
        <input type="checkbox" name="signals" value="monitors" id="sourceSignalMonitors">
      </div>
      <input type="hidden" name="signals" id="sourceSignalFixed" disabled value="">
      <!-- The check editor, as the page renders it: every field fillMonitor
           writes to, and the blocks applyMonitorKind shows and hides. A
           field the editor forgets keeps whatever the DOM last held, and the
           save writes that — which for the TLS boxes would mean one check's
           certificate saved onto the next one. -->
      <h5 id="monitorModalTitle"></h5>
      <input id="monitorId"><input id="monitorName"><input id="monitorTarget">
      <input id="monitorInterval"><input id="monitorTimeout">
      <input id="monitorStatus"><input id="monitorBody">
      <input id="monitorMaxDuration"><input id="monitorHeadersPresent">
      <input id="monitorHeadersMatch"><input id="monitorRequestHeaders">
      <input id="monitorRequestCookies"><input id="monitorAuthUsername">
      <input id="monitorAuthPassword"><input id="monitorAuthToken">
      <input type="checkbox" id="monitorEnabled">
      <select id="monitorKind"><option value="http">http</option>
        <option value="tcp">tcp</option>
        <option value="browser">browser</option></select>
      <select id="monitorAuthType"><option value="">none</option>
        <option value="basic">basic</option></select>
      <div data-tls id="tlsSection">
        <input type="radio" name="tls_mode" value="verify" id="monitorTlsVerify">
        <input type="radio" name="tls_mode" value="expiry_only"
               id="monitorTlsExpiryOnly">
      </div>
      <div data-tls-verify id="tlsCertificateField">
        <textarea id="monitorTlsCertificate"></textarea></div>
      <div data-tls-name id="tlsNameField">
        <input id="monitorTlsExpectedName"></div>
      <div data-forget id="forgetField">
        <input type="checkbox" id="monitorForgetRequest"></div>
      <button class="edit-monitor" data-monitor='{"id":"m1","name":"Payments","kind":"http","target":"https://payments.internal/health","interval_seconds":60,"timeout_seconds":10,"assertions":{},"request":{"headers":{"X-Tenant-Token":"abc"}},"has_credentials":true,"steps":[],"secret_names":[],"enabled":true,"agent_ids":[],"tls":{"mode":"verify","certificate":"-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\\n","expected_name":"payments.internal"}}'></button>
      <button class="edit-monitor" id="editWaived" data-monitor='{"id":"m2","name":"Lab","kind":"http","target":"https://lab.internal/","interval_seconds":60,"timeout_seconds":10,"assertions":{},"request":{},"has_credentials":false,"steps":[],"secret_names":[],"enabled":true,"agent_ids":[],"tls":{"mode":"expiry_only"}}'></button>
      <button id="addMonitorBtn"></button>
      <div class="modal fade" id="monitorModal"></div>

      <div data-kind="elasticsearch" data-needs="logs" id="logPatternField"></div>
      <div data-kind="elasticsearch" data-needs="traces" id="tracePatternField"></div>
      <div data-kind="elasticsearch" data-needs="monitors" id="monitorPatternField"></div>
      <script type="application/json" id="sourceSignals">
        {"elasticsearch": ["logs", "traces", "monitors"], "loki": ["logs"],
         "jaeger": ["traces"], "tempo": ["traces"],
         "victorialogs": ["logs"]}
      </script>
      <!-- Local accounts. One password dialog serves every row, so the row
           has to say which account it is about — to the form as its action,
           and to the person in the heading. A dialog keeping the last row's
           action resets the wrong account's password, and nothing on the
           page or in the audit row would look wrong afterwards. -->
      <button class="reset-password" id="resetBob" data-username="bob"
              data-action="/admin/accounts/bob/password"></button>
      <button class="reset-password" id="resetEve"
              data-username="&lt;img src=x&gt;"
              data-action="/admin/accounts/eve/password"></button>
      <form id="passwordForm">
        <input type="password" name="password"><input type="password" name="confirm">
      </form>
      <code id="passwordFor"></code>

      <form></form></body>`,
      { runScripts: 'outside-only', url: 'http://localhost/admin/config' });

    const w = dom.window;
    global.window = w;
    global.document = w.document;
    w.bootstrap = { Modal: class { constructor() {} show() {}
                                   static getInstance() { return null; }
                                   // The check editor opens its modal
                                   // this way; without it jsdom reports
                                   // an uncaught TypeError per click.
                                   static getOrCreateInstance() {
                                       return new this(); } } };

    const calls = [];
    w.fetch = (url, options) => {
        calls.push(url);
        if (url.includes('/available')) {
            return Promise.resolve({ json: () => Promise.resolve({
                logs: [{ source: 'es',
                         // Five shapes a real cluster holds: an ILM
                         // sequence, Logstash's own date roll-over, a data
                         // stream carrying the Beats version before its
                         // date, a name whose last component is a single
                         // digit, and a name that does not rotate at all.
                         containers: ['app-logs-000001', 'logstash-2026.09.11',
                                      '.ds-heartbeat-8.19.9-2026.09.11-000001',
                                      'app-logs-2', 'payments'] }],
                traces: [], services: ['api-gateway'],
                service_errors: [{ source: 'tempo-down',
                                   error: 'Connection refused' }] }) });
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

/**
 * An identity provider card: the switch, the boxes enabling it needs, and
 * one that is needed only alongside another. Built as the template builds
 * it, so what is measured is config.js against real markup.
 */
function buildProviderCard() {
    const dom = new JSDOM(`<!doctype html><body>
      <form id="ldapForm">
        <input type="checkbox" name="enabled" id="ldapEnabled">
        <input name="server" id="server" data-needed-to-enable>
        <input name="base_dn" id="baseDn" data-needed-to-enable>
        <input name="bind_dn" id="bindDn">
        <input type="password" name="bind_password" id="bindPassword"
               data-needed-to-enable data-needed-with="bind_dn">
        <input name="user_filter" id="userFilter">
      </form>
      </body>`,
      { runScripts: 'outside-only', url: 'http://localhost/admin/config' });
    const w = dom.window;
    global.window = w;
    global.document = w.document;
    w.bootstrap = { Modal: class { constructor() {} show() {}
                                   static getInstance() { return null; }
                                   static getOrCreateInstance() {
                                       return new this(); } },
                    Tab: class { static getOrCreateInstance() {
                        return { show() {} }; } } };
    w.fetch = () => Promise.resolve({ json: () => Promise.resolve({}) });
    w.eval(fs.readFileSync(path.join(ROOT, 'static/js/config.js'), 'utf8'));
    return w;
}

/** What Jinja's autoescape does to text, and to an attribute value. */
function escapeText(value) {
    return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;')
                        .replace(/>/g, '&gt;');
}
function escapeAttribute(value) {
    return escapeText(value).replace(/"/g, '&#34;').replace(/'/g, '&#39;');
}

/**
 * The mapping modal and the table it is opened from, as the server renders
 * them: the role options are real <option> elements and each row carries its
 * own values in a data attribute. Nothing here is built from a string in
 * config.js, which is the point being checked.
 */
function buildMappings(roleNames, mappings) {
    const options = ['<option value="">choose a role…</option>'].concat(
        roleNames.map(name =>
            `<option value="${escapeAttribute(name)}">${
                escapeText(name)}</option>`)).join('');
    const rows = Object.entries(mappings).map(([who, role]) =>
        `<tr><td>${escapeText(who)}</td><td>${escapeText(role)}</td>
         <td><button class="edit-mapping" data-mapping='${
             JSON.stringify({ who, role }).replace(/'/g, '&#39;')
         }'>Edit</button></td></tr>`).join('');
    const dom = new JSDOM(`<!doctype html><body>
      <table id="mappingsTable"><tbody>${rows}</tbody></table>
      <button id="addMappingBtn"></button>
      <form id="mappingForm">
        <h5 id="mappingModalTitle">Add mapping</h5>
        <input type="hidden" name="original" id="mappingOriginal">
        <input name="identifier" id="mappingIdentifier">
        <select name="role" id="mappingRole">${options}</select>
      </form>
      </body>`,
      { runScripts: 'outside-only', url: 'http://localhost/admin/config' });
    const w = dom.window;
    global.window = w;
    global.document = w.document;
    w.bootstrap = { Modal: class { constructor() {} show() {}
                                   static getInstance() { return null; }
                                   // The check editor opens its modal
                                   // this way; without it jsdom reports
                                   // an uncaught TypeError per click.
                                   static getOrCreateInstance() {
                                       return new this(); } } };
    w.fetch = () => Promise.resolve({ json: () => Promise.resolve({}) });
    w.eval(fs.readFileSync(path.join(ROOT, 'static/js/config.js'), 'utf8'));
    return w;
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
    // The separator is kept: `app-logs*` also reaches `app-logsomething`.
    check('the picker offers a rotation-proof pattern first',
          picker.includes('app-logs-*') && !picker.includes('>app-logs*<'),
          picker);
    check('and an exact name as the deliberate alternative',
          picker.includes('>exact<'));

    // A DATE roll-over is the common one — Logstash's own default, legacy
    // Beats indices, a data stream's backing indices — and the old
    // expression stripped only a trailing run of four or more digits, so it
    // handed back `logstash-2026.09.11*` under a button titled "Survives
    // rotation". It did not: the role lost access the next day.
    check('a date-rotated name is stripped back to its stem too',
          picker.includes('logstash-*')
          && !picker.includes('logstash-2026.09.11*'), picker);

    // And a name with nothing to strip has no rotation-proof form. Offering
    // `payments*` as one is the same promise broken the other way: it grants
    // `payments-secrets` as well.
    const rows = Array.from(w.document.querySelectorAll('#targetPickerBody tr'));
    const rowFor = name => rows.find(
        row => row.querySelector('code').textContent === name);
    const onlyExact = name => {
        const row = rowFor(name);
        return row && row.querySelectorAll('.insert-target').length === 1
            && row.querySelector('.insert-target').textContent.trim() === 'exact';
    };
    check('a name that does not rotate is offered only as itself',
          onlyExact('payments'),
          rowFor('payments') ? rowFor('payments').innerHTML : 'no row');

    // What rotates is a DATE and an ILM sequence, and stripping the whole
    // trailing run of digits, dots and dashes takes more than that. These
    // suggestions are written into role grants, so the over-reach is the
    // same fault as the under-reach: `.ds-heartbeat-*` covers a Beats 9.x
    // stream this cluster has never had, and the grant would follow it.
    const heartbeat = rowFor('.ds-heartbeat-8.19.9-2026.09.11-000001');
    check('the version in a data stream name survives the strip',
          heartbeat
          && heartbeat.textContent.includes('.ds-heartbeat-8.19.9-*')
          && !heartbeat.textContent.includes('>.ds-heartbeat-*<'),
          heartbeat ? heartbeat.innerHTML : 'no row for the data stream');

    // `app-logs-2` is a name, not a rotation: stripped to `app-logs-*` it
    // reaches `app-logs-secret-000001` next door.
    check('a one-digit last component is not a rotation suffix',
          onlyExact('app-logs-2'),
          rowFor('app-logs-2') ? rowFor('app-logs-2').innerHTML : 'no row');

    // The services side. A trace store that could not be asked used to be
    // dropped with `except Exception: continue`, so a shorter list of names
    // read as a quiet week.
    const services = build().w;
    services.document.getElementById('pickServices')
            .dispatchEvent(new services.Event('click'));
    await new Promise(resolve => setTimeout(resolve, 150));
    const servicesBody = services.document.getElementById('targetPickerBody');
    check('a trace store that could not be asked is named in the picker',
          servicesBody.textContent.includes('tempo-down')
          && servicesBody.textContent.includes('Connection refused'),
          servicesBody.innerHTML);
    check('and the services the others did see are still offered',
          servicesBody.textContent.includes('api-gateway'),
          servicesBody.innerHTML);

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

    // --- a third signal, and what it broke --------------------------------

    const three = build().w;
    three.applyKind('elasticsearch');
    const all = signalState(three);
    check('a type serving three signals offers all three',
          all.logs.shown && all.traces.shown && all.monitors.shown,
          `logs=${all.logs.shown} traces=${all.traces.shown} ` +
          `monitors=${all.monitors.shown}`);

    // `d-none` hides a checkbox from the reader, not from the form: a hidden
    // CHECKED box is still submitted. Switching type therefore used to send a
    // signal the new type has never heard of.
    const switched = build().w;
    switched.document.getElementById('sourceSignalMonitors').checked = true;
    switched.applyKind('loki');
    check('switching away unticks a signal the new type cannot serve',
          !switched.document.getElementById('sourceSignalMonitors').checked);
    const wouldSubmit = Array.from(switched.document.querySelectorAll(
        '[data-signal] input:checked')).map(box => box.value);
    check('so it is not in what the form would submit',
          !wouldSubmit.includes('monitors'), `would submit ${wouldSubmit}`);

    // Ticking it has to bring somewhere to say WHERE the monitors live, or
    // the source is saved pointing at the log indices.
    const monitorFields = build().w;
    monitorFields.document.getElementById('sourceSignalMonitors').checked = true;
    monitorFields.applyKind('elasticsearch');
    check('ticking monitors reveals its index-pattern field',
          !monitorFields.document.getElementById('monitorPatternField')
                        .classList.contains('d-none'));

    // --- the editor has to FILL the fields it offers ---------------------
    //
    // The save writes every signal block whatever the form says, so a field
    // the editor does not fill is a field that is saved empty. `monitors`
    // was the one it did not fill, and empty means `heartbeat-*,
    // synthetics-*`: an edit made to rename the source, or to rotate its
    // password, silently moved its monitors to Heartbeat's own indices.
    const editing = build().w;
    const sourceButton = (win, name) => Array.from(
        win.document.querySelectorAll('.edit-source'))
        .find(button => JSON.parse(button.dataset.source).name === name);

    sourceButton(editing, 'cluster').dispatchEvent(new editing.Event('click'));
    check('editing a source fills every pattern field it stores',
          editing.document.getElementById('sourceMonitorPatterns').value
              === 'synthetics-prod-*'
          && editing.document.getElementById('sourceLogPatterns').value
              === 'app-*',
          `monitors=${JSON.stringify(
              editing.document.getElementById('sourceMonitorPatterns').value)}`);

    // The modal is one form, reused. Text typed into it and abandoned is
    // still there when the next source is opened, and the save takes it.
    const stale = build().w;
    stale.document.getElementById('addSourceBtn')
         .dispatchEvent(new stale.Event('click'));
    stale.document.getElementById('sourceMonitorPatterns').value = 'typed-in-add-*';
    sourceButton(stale, 'other').dispatchEvent(new stale.Event('click'));
    check('and replaces what the last visit left in them',
          stale.document.getElementById('sourceMonitorPatterns').value
              === 'uptime-*',
          `monitors=${JSON.stringify(
              stale.document.getElementById('sourceMonitorPatterns').value)}`);

    // Add clears it, rather than offering the previous source's patterns as
    // if they were this one's.
    const adding = build().w;
    sourceButton(adding, 'cluster').dispatchEvent(new adding.Event('click'));
    adding.document.getElementById('addSourceBtn')
          .dispatchEvent(new adding.Event('click'));
    check('a new source starts with an empty monitor field',
          adding.document.getElementById('sourceMonitorPatterns').value === '',
          `monitors=${JSON.stringify(
              adding.document.getElementById('sourceMonitorPatterns').value)}`);

    // Switching an identity provider on. The card could be saved with
    // every box empty and switched ON with every box empty: the row counted
    // as a configured directory, refused the other one as "a second
    // directory", and was reported as in force while no sign-in was ever
    // offered through it. The server refuses both; this is the same rule in
    // the browser, and only while the switch is on — a half-filled card is
    // still saveable as the draft somebody is coming back to.
    console.log('enabling a provider');
    const card = buildProviderCard();
    const enabled = card.document.getElementById('ldapEnabled');
    const server = card.document.getElementById('server');
    const bindDn = card.document.getElementById('bindDn');
    const bindPassword = card.document.getElementById('bindPassword');
    const userFilter = card.document.getElementById('userFilter');

    check('a card that is off asks for nothing',
          !server.required && !bindPassword.required);

    enabled.checked = true;
    enabled.dispatchEvent(new card.Event('change'));
    check('switching it on asks for what a sign-in needs',
          server.required
          && card.document.getElementById('baseDn').required);
    check('and for nothing else',
          !userFilter.required);
    check('a bind password is not asked for without a bind DN',
          !bindPassword.required);

    bindDn.value = 'cn=admin,dc=example,dc=com';
    bindDn.dispatchEvent(new card.Event('input'));
    check('naming a service account asks for its password',
          bindPassword.required);

    bindDn.value = '';
    bindDn.dispatchEvent(new card.Event('input'));
    check('and clearing the DN stops asking',
          !bindPassword.required);

    enabled.checked = false;
    enabled.dispatchEvent(new card.Event('change'));
    check('switching it off again asks for nothing, so a draft can be saved',
          !server.required && !bindPassword.required);

    // Direct mappings. A select with nothing selected shows, and SUBMITS,
    // its FIRST option, and the first role is `admin`: a mapping whose role
    // had been deleted came back as `admin`, and so did a new row nobody
    // chose for. Both are asked of the modal the table opens, since that is
    // now the only way a mapping is written.
    console.log('role mappings');
    const ROLES = ['admin', 'developer', 'viewer'];
    const mapped = buildMappings(ROLES, {
        'alice@example.com': 'auditor', 'carol': 'viewer' });
    const editors = mapped.document.querySelectorAll('.edit-mapping');
    const roleField = mapped.document.getElementById('mappingRole');
    const whoField = mapped.document.getElementById('mappingIdentifier');

    editors[0].dispatchEvent(new mapped.Event('click'));
    check('editing a mapping whose role is gone does not choose admin',
          roleField.value === 'auditor', roleField.value);
    check('and the option it lands on says the role no longer exists',
          roleField.selectedOptions[0].textContent.includes('no longer exists')
          && roleField.classList.contains('is-invalid'),
          roleField.selectedOptions[0].textContent);
    check('and the identifier comes with it, as what is being replaced',
          whoField.value === 'alice@example.com'
          && mapped.document.getElementById('mappingOriginal').value
             === 'alice@example.com',
          whoField.value);

    editors[1].dispatchEvent(new mapped.Event('click'));
    check('editing a mapping whose role exists chooses that role',
          roleField.value === 'viewer', roleField.value);
    check('and the role that had gone is no longer offered to anybody else',
          Array.from(roleField.options).every(o => o.value !== 'auditor'),
          Array.from(roleField.options).map(o => o.value).join(','));

    mapped.document.getElementById('addMappingBtn')
          .dispatchEvent(new mapped.Event('click'));
    check('adding starts on no role at all, not on the first one',
          roleField.value === '' && !roleField.classList.contains('is-invalid'),
          roleField.value);
    check('adding starts on an empty identifier, replacing nothing',
          whoField.value === ''
          && mapped.document.getElementById('mappingOriginal').value === ''
          && mapped.document.getElementById('mappingModalTitle').textContent
             === 'Add mapping');

    // The option config.js has to build itself is the one for a role that is
    // gone. Built with createElement and textContent, a role name that is
    // markup is a name rather than a tag — by construction, not by escaping.
    const GONE = 'y</select><b>gone</b> & co';
    const hostile = buildMappings(['admin'], { 'dave': GONE });
    hostile.document.querySelector('.edit-mapping')
           .dispatchEvent(new hostile.Event('click'));
    const hostileRole = hostile.document.getElementById('mappingRole');
    check('a role name is text, not markup',
          hostileRole.querySelector('b') === null
          && hostileRole.value === GONE,
          hostileRole.innerHTML);
    // Character for character, which is the half a parser cannot fake: run
    // through innerHTML the `<b>` is swallowed and the `&` decoded, so the
    // name on screen is not the name that is granting.
    check('and the name on screen is the name that is stored',
          hostileRole.selectedOptions[0].textContent
          === `${GONE} — no longer exists`,
          JSON.stringify(hostileRole.selectedOptions[0].textContent));

    // And values, not attributes: a quote in either one must survive the row
    // and reach the form unchanged, or the save renames somebody.
    const quoted = buildMappings(['q" data-x="1'], { 'w" data-y="1': 'q" data-x="1' });
    quoted.document.querySelector('.edit-mapping')
          .dispatchEvent(new quoted.Event('click'));
    check('a quote cannot end an attribute',
          quoted.document.querySelector('#mappingRole [data-x]') === null
          && quoted.document.querySelector('#mappingForm [data-y]') === null);
    check('and the values survive the round trip exactly',
          quoted.document.getElementById('mappingIdentifier').value
          === 'w" data-y="1'
          && quoted.document.getElementById('mappingRole').value
             === 'q" data-x="1',
          quoted.document.getElementById('mappingRole').value);

    // What a change does, including the two things it used to leave out.
    // The fake server works the change out from what the form SENT, the
    // way the real one does, so nothing on screen comes from the fixture:
    // a group typed into the box has to reach the server to be reported,
    // and clearing the services box has to be what empties it.
    console.log('role change');
    const STORED = { services: ['payment-service'], groups: [] };
    function answerChange(edited) {
        let body = null;
        edited.fetch = (url, options) => {
            if (!url.includes('/preview')) {
                return Promise.resolve({ json: () => Promise.resolve({
                    logs: [], traces: [], services: [] }) });
            }
            body = JSON.parse(options.body);
            const sentGroups = body.groups || [];
            const cleared = (body.services || []).length === 0;
            const change = {
                logs_added: [], logs_removed: [], traces_added: [],
                traces_removed: [], permissions_added: [],
                permissions_removed: [],
                groups_added: sentGroups.filter(g => !STORED.groups.includes(g)),
                groups_removed: STORED.groups.filter(g => !sentGroups.includes(g)),
                services_added: cleared ? ['every service'] : [],
                services_removed: [],
            };
            change.widens = change.groups_added.length > 0
                            || change.services_added.length > 0;
            return Promise.resolve({ json: () => Promise.resolve({
                logs: [], traces: [], services: 'every service',
                permissions: [], warnings: [], reaches_nothing: false,
                reaches_everything: { logs: false, traces: false,
                                      services: cleared },
                change }) });
        };
        return () => body;
    }

    const grouped = build().w;
    const groupedBody = answerChange(grouped);
    type(grouped, 'roleServices', 'payment-service');
    type(grouped, 'roleGroups', 'wdash-developers');
    await settle();
    const groupSaid = grouped.document.getElementById('rolePreview').textContent;
    check('a group added to the role is shown as widening',
          groupSaid.includes('hands the role to groups')
          && groupSaid.includes('wdash-developers')
          && groupSaid.includes('widens'),
          `${groupSaid} | sent ${JSON.stringify(groupedBody())}`);

    const cleared = build().w;
    answerChange(cleared);
    type(cleared, 'roleServices', 'payment-service');
    await settle();
    type(cleared, 'roleServices', '');
    await settle();
    const clearSaid = cleared.document.getElementById('rolePreview').textContent;
    check('clearing the services box shows as a change that widens',
          clearSaid.includes('grants services') && clearSaid.includes('every service')
          && clearSaid.includes('widens'), clearSaid);

    // An exclusion taken off widens, and has to be shown as such: the
    // server tells exclusions from grants, and a page that dropped the new
    // lists would say "narrows access" with nothing under it.
    const unexcluded = build().w;
    unexcluded.fetch = (url) => Promise.resolve({ json: () => Promise.resolve(
        url.includes('/preview')
            ? { logs: [], traces: [], services: ['*'], permissions: [],
                warnings: [], reaches_nothing: false,
                reaches_everything: { logs: false, traces: false, services: false },
                change: { logs_added: [], logs_removed: [], traces_added: [],
                          traces_removed: [], permissions_added: [],
                          permissions_removed: [], groups_added: [],
                          groups_removed: [], services_added: [],
                          services_removed: [], exclusions_added: [],
                          exclusions_removed: ['-payments'], widens: true } }
            : { logs: [], traces: [], services: [] }) });
    type(unexcluded, 'roleServices', '*');
    await settle();
    const unexcludedSaid = unexcluded.document.getElementById('rolePreview').textContent;
    check('an exclusion taken off is shown, and shown as widening',
          unexcludedSaid.includes('stops excluding services')
          && unexcludedSaid.includes('-payments')
          && unexcludedSaid.includes('widens'), unexcludedSaid);

    // The connection test quotes the far end back — "Connected to
    // <distribution> <version> (<cluster name>)" — and only its details
    // were escaped.
    const probed = build().w;
    probed.fetch = () => Promise.resolve({ json: () => Promise.resolve({
        ok: true, message: 'Connected to es <img src=x id=planted-probe>' }) });
    probed.document.getElementById('testSourceBtn').click();
    await settle();
    const probeSaid = probed.document.getElementById('sourceTestResult');
    check('a connection test result is text',
          !probed.document.getElementById('planted-probe')
          && probeSaid.textContent.includes('Connected to es <img'),
          probeSaid.innerHTML);

    const failedProbe = build().w;
    failedProbe.fetch = () => Promise.reject(new Error('<img id=planted-error>'));
    failedProbe.document.getElementById('testSourceBtn').click();
    await settle();
    check('a failed connection test is text too',
          !failedProbe.document.getElementById('planted-error'),
          failedProbe.document.getElementById('sourceTestResult').innerHTML);

    // Delete asks first. onsubmit="return confirm(…)" is an inline handler,
    // which the policy refuses to run, so it never asked.
    const deleting = build().w;
    const asked = [];
    deleting.confirm = (text) => { asked.push(text); return false; };
    const form = deleting.document.getElementById('deleteForm');
    const refused = new deleting.Event('submit', { cancelable: true });
    form.dispatchEvent(refused);
    deleting.confirm = (text) => { asked.push(text); return true; };
    const agreed = new deleting.Event('submit', { cancelable: true });
    form.dispatchEvent(agreed);
    check('delete asks, and stops when the answer is no',
          refused.defaultPrevented && !agreed.defaultPrevented
          && asked[0] === 'Delete lab-<b>es</b>?',
          JSON.stringify({ asked, refused: refused.defaultPrevented,
                           agreed: agreed.defaultPrevented }));

    // The server's warnings reach the page, as text. It sent them — a
    // source it could not list, a colon that names no source — and nothing
    // showed them.
    const warned = build().w;
    warned.fetch = (url) => Promise.resolve({ json: () => Promise.resolve(
        url.includes('/preview')
            ? { logs: [], traces: [], services: 'every service', permissions: [],
                warnings: ["'staging:*' is read as a name: <b id=planted>x</b>"],
                reaches_nothing: false,
                reaches_everything: { logs: false, traces: false, services: true },
                change: null }
            : { logs: [], traces: [], services: [] }) });
    type(warned, 'roleContainers', 'staging:*');
    await settle();
    const warnedSaid = warned.document.getElementById('rolePreview');
    check('the server\'s warnings are shown, as text',
          warnedSaid.textContent.includes("'staging:*' is read as a name")
          && !warned.document.getElementById('planted'),
          warnedSaid.innerHTML);

    // A source that could not be listed is not a pattern that matched
    // nothing. The verdict said "matches nothing on this installation" under
    // a correct pattern whenever the backend was down — which is what a typo
    // looks like, and the obvious fix for a typo is a wider pattern.
    const unlisted = build().w;
    const down = { source: 'loki-<b id=planted-source>down</b>', containers: [],
                   count: 0, total: 0, error: 'connection refused' };
    const answering = { source: 'es', containers: [], count: 0, total: 4 };
    let entries = [down];
    unlisted.fetch = (url) => Promise.resolve({ json: () => Promise.resolve(
        url.includes('/preview')
            ? { logs: entries, traces: [], services: 'every service',
                permissions: [], warnings: ['loki-down could not be listed'],
                reaches_nothing: false,
                reaches_everything: { logs: false, traces: false, services: true },
                change: null }
            : { logs: [], traces: [], services: [] }) });
    type(unlisted, 'roleContainers', 'app-*');
    await settle();
    let unlistedSaid = verdict(unlisted, 'roleContainers');
    check('a source that did not answer is "could not be checked", not "matches nothing"',
          /could not be checked/i.test(unlistedSaid)
          && unlistedSaid.includes('loki-<b id=planted-source>down</b>')
          && !/matches nothing/i.test(unlistedSaid)
          && !unlisted.document.getElementById('planted-source'), unlistedSaid);

    entries = [answering, down];
    type(unlisted, 'roleContainers', 'app-* ');
    await settle();
    unlistedSaid = verdict(unlisted, 'roleContainers');
    check('and says which source it could not check beside one that answered',
          /could not be checked/i.test(unlistedSaid)
          && !/matches nothing/i.test(unlistedSaid), unlistedSaid);

    entries = [answering];
    type(unlisted, 'roleContainers', 'app-*  ');
    await settle();
    check('a source that answered with nothing still matches nothing',
          /matches nothing/i.test(verdict(unlisted, 'roleContainers')),
          verdict(unlisted, 'roleContainers'));

    // ---------------------------------------------------------------------
    // The check editor's TLS boxes
    //
    // A certificate is public and is shown back — that is why it lives beside
    // the request rather than in the secret box — so the editor has to fill
    // it, and has to clear it for the next check. What must NOT be carried
    // over is the "forget what this check sends" tick: it empties a check's
    // request, and inheriting it from the last modal would empty one nobody
    // asked about.
    // ---------------------------------------------------------------------
    const checks = build().w;
    const hidden = (id) => checks.document.getElementById(id)
        .classList.contains('d-none');

    checks.document.querySelector('.edit-monitor')
        .dispatchEvent(new checks.Event('click'));
    check('the pasted certificate is shown back',
          checks.document.getElementById('monitorTlsCertificate').value
              .includes('BEGIN CERTIFICATE'),
          checks.document.getElementById('monitorTlsCertificate').value);
    check('and the name it is expected to carry',
          checks.document.getElementById('monitorTlsExpectedName').value
              === 'payments.internal');
    check('a verifying check shows both boxes',
          !hidden('tlsCertificateField') && !hidden('tlsNameField'));
    check('a check that sends something is offered the way to stop',
          !hidden('forgetField'));
    check('and the tick starts clear',
          !checks.document.getElementById('monitorForgetRequest').checked);

    checks.document.getElementById('monitorForgetRequest').checked = true;
    checks.document.getElementById('editWaived')
        .dispatchEvent(new checks.Event('click'));
    check('the next check does not inherit the last one\'s certificate',
          checks.document.getElementById('monitorTlsCertificate').value === ''
          && checks.document.getElementById('monitorTlsExpectedName').value === '',
          checks.document.getElementById('monitorTlsCertificate').value);
    check('nor its tick to forget what it sends',
          !checks.document.getElementById('monitorForgetRequest').checked);
    check('a check that does not verify has its radio chosen',
          checks.document.getElementById('monitorTlsExpiryOnly').checked
          && !checks.document.getElementById('monitorTlsVerify').checked);
    check('and is not offered boxes that would be refused',
          hidden('tlsCertificateField') && hidden('tlsNameField'));
    check('a check that sends nothing is not offered a way to stop',
          hidden('forgetField'));

    // Hidden is not enough: `d-none` hides a box and the browser still
    // submits what is in it. Ticking "do not verify" over a pasted
    // certificate posted the certificate anyway, and the save was refused —
    // "Naming a certificate to trust and then not verifying it are opposite
    // instructions" — about a textarea that was no longer on screen. A
    // disabled control is not submitted, and keeps its value for when the
    // block comes back.
    checks.document.querySelector('.edit-monitor')
        .dispatchEvent(new checks.Event('click'));
    check('a refusable certificate is on screen and enabled to begin with',
          !hidden('tlsCertificateField')
          && !checks.document.getElementById('monitorTlsCertificate').disabled);
    checks.document.getElementById('monitorTlsExpiryOnly').checked = true;
    checks.document.getElementById('monitorTlsExpiryOnly')
        .dispatchEvent(new checks.Event('change'));
    check('ticking "do not verify" stops the certificate being submitted',
          checks.document.getElementById('monitorTlsCertificate').disabled);
    check('and the expected name with it',
          checks.document.getElementById('monitorTlsExpectedName').disabled);
    check('the certificate is kept, not thrown away',
          checks.document.getElementById('monitorTlsCertificate').value
              .includes('BEGIN CERTIFICATE'));
    checks.document.getElementById('monitorTlsVerify').checked = true;
    checks.document.getElementById('monitorTlsVerify')
        .dispatchEvent(new checks.Event('change'));
    check('and comes back, enabled, when verification does',
          !checks.document.getElementById('monitorTlsCertificate').disabled
          && checks.document.getElementById('monitorTlsCertificate').value
              .includes('BEGIN CERTIFICATE'));

    checks.document.getElementById('monitorKind').value = 'tcp';
    checks.applyMonitorKind();
    check('a tcp check submits no TLS setting at all',
          checks.document.getElementById('monitorTlsCertificate').disabled
          && checks.document.getElementById('monitorTlsExpiryOnly').disabled);
    checks.document.getElementById('monitorKind').value = 'browser';
    checks.applyMonitorKind();
    check('a journey submits no expected name',
          checks.document.getElementById('monitorTlsExpectedName').disabled);
    check('nor a tick to forget what it sends',
          checks.document.getElementById('monitorForgetRequest').disabled);
    checks.document.getElementById('monitorKind').value = 'http';
    checks.applyMonitorKind();

    checks.document.getElementById('addMonitorBtn')
        .dispatchEvent(new checks.Event('click'));
    check('a new check starts by verifying',
          checks.document.getElementById('monitorTlsVerify').checked
          && checks.document.getElementById('monitorTlsCertificate').value === '');

    // A tcp check opens a socket and never sees a certificate, and a journey
    // has no name to expect: measured, a pinned key is accepted whatever name
    // the certificate carries.
    checks.document.getElementById('monitorKind').value = 'tcp';
    checks.applyMonitorKind();
    check('a tcp check is offered no TLS section at all', hidden('tlsSection'));
    checks.document.getElementById('monitorKind').value = 'browser';
    checks.applyMonitorKind();
    check('a journey may name a certificate but not a name',
          !hidden('tlsCertificateField') && hidden('tlsNameField'));

    console.log('\nlocal accounts');
    const accounts = build().w;
    const resetForm = accounts.document.getElementById('passwordForm');
    const resetWho = accounts.document.getElementById('passwordFor');
    resetForm.querySelector('input[name=password]').value = 'left-behind';

    check('a password dialog opened from nowhere has no action',
          !resetForm.getAttribute('action'));

    accounts.document.getElementById('resetBob')
        .dispatchEvent(new accounts.Event('click'));
    check('the dialog points at the account whose row opened it',
          resetForm.getAttribute('action') === '/admin/accounts/bob/password');
    check('and says whose password it is about', resetWho.textContent === 'bob');
    check('a password left in the box from last time is cleared',
          resetForm.querySelector('input[name=password]').value === '');

    accounts.document.getElementById('resetEve')
        .dispatchEvent(new accounts.Event('click'));
    check('opening a second row repoints it rather than keeping the first',
          resetForm.getAttribute('action') === '/admin/accounts/eve/password');
    // A username is somebody else's input, and it is written into the
    // heading. textContent, never innerHTML.
    check('a username is written as text, not as markup',
          resetWho.children.length === 0
          && resetWho.textContent === '<img src=x>');

    console.log(failures.length ? `\n${failures.length} failure(s)`
                                : '\nall role editor checks passed');
    process.exit(failures.length ? 1 : 0);
})();
