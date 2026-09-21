/**
 * The configuration screen.
 *
 * Two editors, both driven by data attributes on the row being edited rather
 * than by fetching the object again: the page already rendered it, and a
 * second request would only introduce a way for the two to disagree.
 *
 * Nothing here decides anything. Every value is re-validated on the server,
 * because a form is a suggestion.
 */

function setValue(id, value) {
    const element = document.getElementById(id);
    if (element) element.value = value === null || value === undefined ? '' : value;
}

function setChecked(id, value) {
    const element = document.getElementById(id);
    if (element) element.checked = Boolean(value);
}

/**
 * Show only the fields the selected source type actually uses.
 *
 * `data-kind` takes a space-separated list, because some fields belong to
 * more than one backend — a tenant means something to both Loki and
 * VictoriaLogs. An exact string comparison hid the field for every kind but
 * the first one listed, which looks like the field not existing.
 */
/** {kind: [signals]}, rendered by the server from SOURCE_KINDS. */
function signalMap() {
    const element = document.getElementById('sourceSignals');
    if (!element) return {};
    try {
        return JSON.parse(element.textContent);
    } catch (e) {
        return {};
    }
}

function applyKind(kind) {
    document.querySelectorAll('[data-kind]').forEach(element => {
        const kinds = (element.dataset.kind || '').split(/\s+/);
        element.classList.toggle('d-none', !kinds.includes(kind));
    });

    // Every signal the type serves is SHOWN, always. Hiding the row for a
    // type with one signal left a labelled area with nothing in it, which
    // reads as a control that failed to render rather than as a type with no
    // choice to make.
    //
    // With one signal the box is ticked and disabled — visible, obviously
    // fixed, not editable. A disabled checkbox submits nothing, so a hidden
    // input carries the value instead; without it the save fails with "a
    // source has to serve at least one signal", which is a true sentence
    // about a form the person cannot argue with.
    const serves = (signalMap()[kind] || ['logs']);
    const single = serves.length === 1;

    document.querySelectorAll('[data-signal]').forEach(element => {
        const signal = element.dataset.signal;
        const box = element.querySelector('input');
        const offered = serves.includes(signal);
        element.classList.toggle('d-none', !offered);
        if (!box) return;
        box.disabled = single;
        // A box the type cannot serve must never stay ticked. Hiding it is
        // not enough: `d-none` hides it from the reader, not from the form,
        // and a hidden checked box is still submitted — so a source switched
        // from Elasticsearch to Loki would arrive claiming to serve a signal
        // Loki has never heard of.
        //
        // This used to read "only the single case needs to set anything,
        // because with two signals `more than one` means `both`". That was
        // true while there were two. It stopped being true the moment there
        // were three, and it stopped being true silently.
        box.checked = single ? offered : (box.checked && offered);
    });

    const carrier = document.getElementById('sourceSignalFixed');
    if (carrier) {
        carrier.value = single ? serves[0] : '';
        carrier.disabled = !single;
    }
    applySignals();
}

/**
 * Show the per-signal fields for the signals actually ticked.
 *
 * Trace index patterns on a source that only serves logs are a box that does
 * nothing, and somebody will fill it in and wonder why nothing changed.
 */
function applySignals() {
    // Disabled boxes are still ticked and still count: they are the fixed
    // signal of a single-signal type, and their fields belong on the form.
    const chosen = Array.from(
        document.querySelectorAll('[data-signal] input:checked'))
        .map(box => box.value);

    document.querySelectorAll('[data-needs]').forEach(element => {
        const needed = element.dataset.needs;
        const hiddenByKind = (element.dataset.kind || '')
            .split(/\s+/).includes(document.getElementById('sourceKind')?.value)
            === false;
        element.classList.toggle('d-none', hiddenByKind || !chosen.includes(needed));
    });
}

document.querySelectorAll('[data-signal] input').forEach(box => {
    box.addEventListener('change', applySignals);
});

// ---------------------------------------------------------------- sources

function fillSource(source) {
    const isNew = !source;
    document.getElementById('sourceModalTitle').textContent =
        isNew ? 'Add source' : `Edit ${source.name}`;

    setValue('sourceId', isNew ? '' : source.id);
    setValue('sourceName', isNew ? '' : source.name);
    const signals = isNew ? ['logs'] : (source.signals || [source.signal]);
    document.querySelectorAll('[data-signal] input').forEach(box => {
        box.checked = signals.includes(box.value);
    });
    setValue('sourceKind', isNew ? 'elasticsearch' : source.kind);
    setValue('sourceUrl', isNew ? '' : source.config.url);
    setValue('sourceUsername', isNew ? '' : source.config.username);
    // Per signal, with a fall back to the flat key so a source stored before
    // one row could serve two signals still fills its form.
    const perSignal = (signal, field) => {
        if (isNew) return '';
        const block = source.config[signal] || {};
        const value = block[field] !== undefined
            ? block[field] : source.config[field];
        return (value || []).join(', ');
    };
    setValue('sourceLogPatterns', perSignal('logs', 'index_patterns'));
    setValue('sourceTracePatterns', perSignal('traces', 'index_patterns'));
    // Monitors too. Left out, the box kept whatever the DOM last held — the
    // empty initial value, or text typed into a previous Add — and the save
    // writes every signal block unconditionally, so an edit made for any
    // other reason (a rename, a password) stored `monitors.index_patterns:
    // []` and the source silently fell back to `heartbeat-*, synthetics-*`.
    setValue('sourceMonitorPatterns', perSignal('monitors', 'index_patterns'));
    setValue('sourceExcludes', perSignal('logs', 'exclude_patterns'));
    setValue('sourceTenant', isNew ? '' : source.config.tenant);
    setValue('sourceStreamLabel', isNew ? '' : source.config.stream_label);
    setValue('sourceStreamField', isNew ? '' : source.config.stream_field);
    setChecked('sourceVerify', isNew ? true : source.config.verify_certs);
    setChecked('sourceEnabled', isNew ? true : source.enabled);

    // Never prefill a password field: the value is not available to prefill
    // with, and an empty box that means "keep what is stored" has to say so.
    setValue('sourcePassword', '');
    const hint = document.getElementById('sourcePasswordHint');
    if (hint && !isNew) {
        hint.textContent = source.has_secret
            ? 'A password is stored. Leave blank to keep it.'
            : 'No password stored.';
    }

    document.getElementById('sourceTestResult').innerHTML = '';
    applyKind(isNew ? 'elasticsearch' : source.kind);

    // Type and signal are immutable once saved: changing them would turn the
    // record into a different source while keeping its identity, and anything
    // referring to it would silently start reading somewhere else.
    ['sourceKind', 'sourceSignal'].forEach(id => {
        const element = document.getElementById(id);
        if (element) element.disabled = !isNew;
    });
}

document.getElementById('addSourceBtn')?.addEventListener('click', () => fillSource(null));

document.querySelectorAll('.edit-source').forEach(button => {
    button.addEventListener('click', () => fillSource(JSON.parse(button.dataset.source)));
});

document.getElementById('sourceKind')?.addEventListener('change', event => {
    applyKind(event.target.value);
});

document.getElementById('testSourceBtn')?.addEventListener('click', async () => {
    const target = document.getElementById('sourceTestResult');
    const button = document.getElementById('testSourceBtn');

    target.innerHTML = '<div class="text-muted"><span class="spinner-border ' +
        'spinner-border-sm"></span> Connecting…</div>';
    button.disabled = true;

    try {
        const response = await fetch('/admin/api/sources/test', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                id: document.getElementById('sourceId').value || null,
                kind: document.getElementById('sourceKind').value,
                url: document.getElementById('sourceUrl').value,
                username: document.getElementById('sourceUsername').value,
                password: document.getElementById('sourcePassword').value,
                verify_certs: document.getElementById('sourceVerify').checked,
            }),
        });
        const result = await response.json();
        const tone = result.ok ? 'success' : 'danger';
        const icon = result.ok ? 'check' : 'triangle-exclamation';
        const detail = typeof result.details === 'string' && !result.ok
            ? `<div class="mt-1" style="font-size:.75rem;opacity:.8">${
                  escapeHtml(result.details)}</div>`
            : '';
        // The message quotes the far end — "Connected to <distribution>
        // <version> (<cluster name>)" — and the far end is whatever the URL
        // points at, over plain http as often as not. Only the details
        // were escaped.
        target.innerHTML = `<div class="alert alert-${tone} py-2 mb-0">` +
            `<i class="fas fa-${icon}"></i> ${escapeHtml(result.message || result.error)}${detail}</div>`;
    } catch (error) {
        target.innerHTML = '<div class="alert alert-danger py-2 mb-0">' +
            'The test could not be run: ' + escapeHtml(error.message) + '</div>';
    } finally {
        button.disabled = false;
    }
});

// ------------------------------------------------------------------ roles

function fillRole(role) {
    const isNew = !role;
    document.getElementById('roleModalTitle').textContent =
        isNew ? 'Add role' : `Edit ${role.name}`;

    setValue('roleName', isNew ? '' : role.name);
    setValue('roleDescription', isNew ? '' : role.description);
    // Checkboxes, not a text field: a typed name WDash does not know grants
    // nothing while looking configured, which is the whole reason the
    // catalogue exists.
    const held = new Set(isNew ? [] : (role.permissions || []));
    document.querySelectorAll('#rolePermissions input[name="permissions"]')
        .forEach(box => { box.checked = held.has(box.value); });
    setValue('roleGroups', isNew ? '' : (role.groups || []).join('\n'));
    setValue('roleContainers', isNew ? '' : (role.containers || []).join('\n'));
    setValue('roleTraceContainers', isNew ? '' : (role.trace_containers || []).join('\n'));
    // null means unrestricted, and the form says so; an empty box must
    // therefore stay empty rather than being filled with anything.
    setValue('roleServices',
             isNew || role.services === null ? '' : (role.services || []).join('\n'));

    const nameField = document.getElementById('roleName');
    if (nameField) nameField.readOnly = !isNew;   // renaming would orphan mappings

    // The server refuses a "create" that names an existing role. Saving over a
    // working role because of a trailing space is not an edit anybody meant.
    setValue('roleMode', isNew ? 'create' : 'edit');

    // Show the verdicts straight away. Opening an existing role and seeing
    // nothing until you touch a field would make the feedback look like a
    // property of editing rather than of the role.
    if (typeof schedulePreview === 'function') schedulePreview();
}

// Delete asks first. It was `onsubmit="return confirm(…)"`, an inline
// handler, which a script-src without 'unsafe-inline' refuses to run — so it
// never asked, and Delete deleted on the first click. The text comes from
// the attribute, as text.
document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', event => {
        if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
});

document.getElementById('addRoleBtn')?.addEventListener('click', () => fillRole(null));

document.querySelectorAll('.edit-role').forEach(button => {
    button.addEventListener('click', () => fillRole(JSON.parse(button.dataset.role)));
});


/* ------------------------------------------------------------------------
 * Local accounts.
 *
 * One password dialog serves every row, so the row has to say which account
 * it is about — both to the form, as its action, and to the person, in the
 * heading. A shared dialog that keeps the last account's action is how a
 * password reset lands on the wrong account, and neither the page nor the
 * audit row would look wrong afterwards.
 * ---------------------------------------------------------------------- */
document.querySelectorAll('.reset-password').forEach(button => {
    button.addEventListener('click', () => {
        const form = document.getElementById('passwordForm');
        const who = document.getElementById('passwordFor');
        if (form) { form.setAttribute('action', button.dataset.action); }
        // textContent, not innerHTML: a username is somebody else's input.
        if (who) { who.textContent = button.dataset.username; }
        form?.querySelectorAll('input[type=password]')
            .forEach(field => { field.value = ''; });
    });
});


/* ------------------------------------------------------------------------
 * Boundary fields.
 *
 * These stay free text, and that is a decision rather than an omission.
 * Containers rotate: a role granted `app-logs-000001` by name silently loses
 * access the day `-000002` appears, which is a worse failure than a typo and a
 * much quieter one. Patterns are what survive rotation.
 *
 * So the danger is not typing — it is typing blind. Two things fix that:
 * every keystroke is matched against what actually exists, and what exists is
 * one click away.
 *
 * The matching happens on the SERVER. Reimplementing the pattern language here
 * would give the product two of them under one name, which is a bug this
 * codebase has already had once.
 * --------------------------------------------------------------------- */

let availableTargets = null;

async function loadAvailableTargets() {
    if (availableTargets) return availableTargets;
    const response = await fetch('/admin/api/available');
    availableTargets = await response.json();
    return availableTargets;
}

function boundaryLines(id) {
    return (document.getElementById(id)?.value || '')
        .replace(/,/g, '\n').split('\n').map(v => v.trim()).filter(Boolean);
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"]/g, c =>
        ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
}

/** Render one field's verdict: what it matches, and whether that is alarming. */
function showVerdict(id, entries, everything, isServices) {
    const holder = document.querySelector(`.boundary-verdict[data-for="${id}"]`);
    if (!holder) return;

    const written = boundaryLines(id);

    if (isServices && !written.length) {
        holder.innerHTML = '<div class="text-warning" style="font-size:.75rem">' +
            '<i class="fas fa-globe"></i> every service</div>';
        return;
    }
    if (!written.length) {
        holder.innerHTML = '<div class="text-muted" style="font-size:.75rem">' +
            'grants nothing</div>';
        return;
    }
    if (isServices) {
        holder.innerHTML = `<div class="text-muted" style="font-size:.75rem">` +
            `${written.length} service pattern${written.length === 1 ? '' : 's'}</div>`;
        return;
    }

    const total = entries.reduce((sum, e) => sum + (e.total || 0), 0);
    const matched = entries.reduce((sum, e) => sum + (e.count || 0), 0);
    // A source the server could not list is not one the pattern matched
    // nothing in. Said as "matches nothing", a correct pattern read as a
    // typo whenever a backend was down.
    const unlisted = entries.filter(e => e.error).map(e => e.source);

    if (!matched && unlisted.length) {
        holder.innerHTML = '<div class="text-warning" style="font-size:.75rem">' +
            '<i class="fas fa-circle-question"></i> could not be checked: ' +
            escapeHtml(unlisted.join(', ')) + ' did not answer</div>';
        return;
    }
    if (!matched) {
        // Usually a typo, and it was invisible until somebody complained.
        holder.innerHTML = '<div class="text-danger" style="font-size:.75rem">' +
            '<i class="fas fa-triangle-exclamation"></i> matches nothing on ' +
            'this installation</div>';
        return;
    }
    if (everything) {
        // The dangerous direction: `*` where `app-*` was meant looks like a
        // working pattern and grants the whole cluster.
        holder.innerHTML = '<div class="text-warning" style="font-size:.75rem">' +
            `<i class="fas fa-globe"></i> <strong>everything</strong> ` +
            `(${matched} of ${total})</div>`;
        return;
    }

    const sample = entries.flatMap(e => e.containers).slice(0, 3).map(escapeHtml);
    holder.innerHTML = `<div class="text-success" style="font-size:.75rem">` +
        `<i class="fas fa-check"></i> ${matched} of ${total}: ` +
        `<code>${sample.join(', ')}</code>` +
        (matched > sample.length ? ` +${matched - sample.length}` : '') + '</div>';
}

let previewTimer = null;

function schedulePreview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(runPreview, 350);
}

async function runPreview() {
    const services = boundaryLines('roleServices');
    let result;
    try {
        const response = await fetch('/admin/api/roles/preview', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                permissions: [...document.querySelectorAll(
                    '#rolePermissions input[name="permissions"]:checked')]
                    .map(box => box.value),
                containers: boundaryLines('roleContainers'),
                trace_containers: boundaryLines('roleTraceContainers'),
                services,
                // Who gets the role is part of what a change does: adding a
                // directory group hands the role to everybody in it.
                groups: boundaryLines('roleGroups'),
                // Editing, so the server can say what CHANGES rather than
                // only what the result is.
                name: document.getElementById('roleMode')?.value === 'edit'
                    ? document.getElementById('roleName')?.value : null,
            }),
        });
        result = await response.json();
    } catch (error) {
        return;                       // a failed preview must not block editing
    }

    showVerdict('roleContainers', result.logs, result.reaches_everything.logs, false);
    showVerdict('roleTraceContainers', result.traces,
                result.reaches_everything.traces, false);
    showVerdict('roleServices', [], false, true);

    const summary = document.getElementById('rolePreview');
    if (!summary) return;

    const parts = [];

    if (result.reaches_nothing) {
        parts.push('<div class="alert alert-warning py-2 mb-2" ' +
            'style="font-size:.8rem"><i class="fas fa-triangle-exclamation"></i> ' +
            '<strong>This role would reach no data at all.</strong> That is a ' +
            'valid choice, and it is also what a mistyped pattern looks like.</div>');
    }

    // What the server could not settle — a source it could not list, a
    // colon that names no source. It sent these and nothing showed them.
    (result.warnings || []).forEach(warning => {
        parts.push('<div class="alert alert-warning py-2 mb-2" style="font-size:.8rem">' +
            '<i class="fas fa-triangle-exclamation"></i> ' +
            escapeHtml(warning) + '</div>');
    });

    const change = result.change;
    if (change && CHANGE_KEYS.some(key => (change[key] || []).length)) {
        parts.push(renderChange(change));
    }

    summary.innerHTML = parts.join('');
}

/**
 * What this edit changes, rather than what it results in.
 *
 * The end state is already on the form; the delta is what an access review is
 * about. A mistyped pattern produces a plausible-looking count and a
 * completely different set — "grants 3 containers it did not have" is the
 * sentence that catches it.
 */
/**
 * Every list the server's change block can carry. Services and groups were
 * missing, so clearing a role's services box — every service, the widest
 * value that box holds — showed no change at all.
 */
const CHANGE_KEYS = [
    'logs_added', 'logs_removed', 'traces_added', 'traces_removed',
    'services_added', 'services_removed', 'exclusions_added', 'exclusions_removed',
    'permissions_added', 'permissions_removed',
    'groups_added', 'groups_removed',
];

function renderChange(change) {
    const list = (label, items, tone) => (items || []).length
        ? `<div class="${tone}"><strong>${label}</strong> ` +
          items.slice(0, 6).map(escapeHtml).map(v => `<code>${v}</code>`).join(' ') +
          (items.length > 6 ? ` +${items.length - 6} more` : '') + '</div>'
        : '';

    return `<div class="alert alert-${change.widens ? 'warning' : 'secondary'} ` +
        `py-2 mb-0" style="font-size:.8rem">` +
        `<div class="mb-1"><i class="fas fa-${change.widens ? 'arrow-up-right-dots' : 'code-compare'}"></i> ` +
        `<strong>${change.widens ? 'This change widens access.' : 'This change narrows access.'}</strong></div>` +
        list('grants logs:', change.logs_added, 'text-warning') +
        list('removes logs:', change.logs_removed, 'text-muted') +
        list('grants traces:', change.traces_added, 'text-warning') +
        list('removes traces:', change.traces_removed, 'text-muted') +
        list('grants services:', change.services_added, 'text-warning') +
        list('removes services:', change.services_removed, 'text-muted') +
        list('stops excluding services:', change.exclusions_removed, 'text-warning') +
        list('excludes services:', change.exclusions_added, 'text-muted') +
        list('grants permissions:', change.permissions_added, 'text-warning') +
        list('removes permissions:', change.permissions_removed, 'text-muted') +
        list('hands the role to groups:', change.groups_added, 'text-warning') +
        list('takes it from groups:', change.groups_removed, 'text-muted') +
        '</div>';
}

document.querySelectorAll('.boundary-field').forEach(field => {
    field.addEventListener('input', schedulePreview);
});
document.getElementById('roleGroups')
    ?.addEventListener('input', schedulePreview);
document.getElementById('rolePermissions')
    ?.addEventListener('change', schedulePreview);

/* ---- browse what exists ---- */

/*
 * The picker opens on top of the role editor, and Bootstrap does not support
 * that: every modal gets the same z-index, so paint order comes down to which
 * one appears first in the document — and the picker is declared before the
 * editor it is opened from. It opened, it loaded, and it was invisible behind
 * the form.
 *
 * Raised here rather than by reordering the template, because the template
 * order would be a fix nothing explains and the next edit undoes.
 */
const STACK_STEP = 20;

function stackAbove(modal) {
    const beneath = document.querySelectorAll('.modal.show').length;
    if (!beneath) return;              // opened on its own; leave the default
    modal.style.zIndex = 1055 + beneath * STACK_STEP;
}

function stackBackdrop(beneathCount) {
    if (!beneathCount) return;
    const backdrops = document.querySelectorAll('.modal-backdrop');
    const own = backdrops[backdrops.length - 1];
    // Above the editor, below this modal: the editor must dim, not vanish.
    if (own) own.style.zIndex = 1050 + beneathCount * STACK_STEP;
}

const picker = document.getElementById('targetPicker');
if (picker) {
    let beneath = 0;
    picker.addEventListener('show.bs.modal', () => {
        beneath = document.querySelectorAll('.modal.show').length;
        stackAbove(picker);
    });
    // The backdrop element does not exist until the modal is shown.
    picker.addEventListener('shown.bs.modal', () => stackBackdrop(beneath));
    picker.addEventListener('hidden.bs.modal', () => {
        picker.style.zIndex = '';
        // Bootstrap strips `modal-open` whenever ANY modal closes, so closing
        // the picker leaves the still-open editor scrolling the page behind
        // it instead of itself.
        if (document.querySelector('.modal.show')) {
            document.body.classList.add('modal-open');
        }
    });
}

document.querySelectorAll('.pick-target').forEach(button => {
    button.addEventListener('click', async () => {
        const kind = button.dataset.kind;
        const targetId = button.dataset.target;
        const body = document.getElementById('targetPickerBody');
        const title = document.getElementById('targetPickerTitle');

        title.textContent = kind === 'services' ? 'Services seen in traces'
                                                : `Available ${kind} containers`;
        body.innerHTML = '<div class="text-muted">Loading…</div>';
        new bootstrap.Modal(document.getElementById('targetPicker')).show();

        const available = await loadAvailableTargets();

        if (kind === 'services') {
            // A trace store that did not answer is named, the way an
            // unlistable log source already is. Dropped, its services were
            // simply missing from the list, and a shorter list of names
            // looks exactly like a quiet week.
            const problems = (available.service_errors || []).map(entry =>
                `<div class="text-warning mb-2" style="font-size:.8rem">
                   <i class="fas fa-triangle-exclamation"></i>
                   <strong>${escapeHtml(entry.source)}</strong> could not be
                   asked: ${escapeHtml(entry.error)}</div>`).join('');
            const names = available.services.map(name =>
                `<button type="button" class="btn btn-sm btn-outline-secondary me-1 mb-1 insert-target"
                         data-target="${targetId}" data-value="${escapeHtml(name)}">
                   ${escapeHtml(name)}</button>`).join('');
            // "No services seen" is a statement about the last 24 hours. It
            // is only true when every store answered.
            body.innerHTML = problems + (names || (problems ? ''
                : '<div class="text-muted">No services seen in the last 24 hours.</div>'));
        } else {
            body.innerHTML = (available[kind] || []).map(entry => {
                if (entry.error) {
                    return `<div class="mb-3"><strong>${escapeHtml(entry.source)}</strong>
                            <div class="text-warning" style="font-size:.8rem">
                            ${escapeHtml(entry.error)}</div></div>`;
                }
                if (!entry.containers.length) {
                    return `<div class="mb-3"><strong>${escapeHtml(entry.source)}</strong>
                            <div class="text-muted" style="font-size:.8rem">nothing here</div></div>`;
                }
                const rows = entry.containers.map(name => {
                    // Strip the trailing rotation suffix to suggest a pattern
                    // that survives the next roll-over.
                    //
                    // What rotates is a DATE (`2026.09.11`, `2026-09-11`) and
                    // an ILM sequence (`-000001`), either or both, and only
                    // those are taken. `-000001` alone was stripped once, so
                    // every date-rotated name — Logstash's own
                    // `logstash-2026.09.11`, Beats'
                    // `filebeat-8.14.0-2026.09.11`, a data stream's
                    // `.ds-logs-app-default-2026.09.11-000001` — came back
                    // with its date still on it under a button titled
                    // "Survives rotation": the role lost access the next day.
                    //
                    // The whole trailing run of digits, dots and dashes is
                    // too much in the other direction, and these suggestions
                    // are written into role GRANTS. It ate the Beats version
                    // (`.ds-heartbeat-8.19.9-...` offered as
                    // `.ds-heartbeat-*`, which covers a 9.x stream nobody has
                    // seen yet) and turned `app-logs-2`, a name, into
                    // `app-logs-*`, which reaches `app-logs-secret-000001`.
                    const ROTATION = /[-.](\d{4}[-.]\d{2}[-.]\d{2}|\d{4,})$/;
                    let stem = name, separator = '';
                    for (let match = stem.match(ROTATION); match;
                         match = stem.match(ROTATION)) {
                        separator = stem[match.index];
                        stem = stem.slice(0, match.index);
                    }
                    // The separator is kept, so `app-logs-*` rather than
                    // `app-logs*` — the wider one also reaches
                    // `app-logsomething`.
                    const stripped = stem + separator;
                    // Nothing to strip means nothing rotates: `payments` has
                    // no rotation-proof form, and offering `payments*` as one
                    // is the same promise broken a different way.
                    const rotating = stripped !== name;
                    const suggested = rotating
                        ? `<button type="button" class="btn btn-sm btn-outline-primary insert-target"
                                data-target="${targetId}" data-value="${escapeHtml(stripped + '*')}"
                                title="Survives rotation">${escapeHtml(stripped + '*')}</button>`
                        : '';
                    return `<tr>
                      <td><code>${escapeHtml(name)}</code></td>
                      <td class="text-end text-nowrap">
                        ${suggested}
                        <button type="button" class="btn btn-sm btn-outline-secondary insert-target"
                                data-target="${targetId}" data-value="${escapeHtml(name)}"
                                title="Pins the role to this exact container">exact</button>
                      </td></tr>`;
                }).join('');
                return `<div class="mb-3"><strong>${escapeHtml(entry.source)}</strong>
                        <table class="table table-hover table-dense mb-0">${rows}</table></div>`;
            }).join('') || '<div class="text-muted">No sources configured.</div>';
        }

        body.querySelectorAll('.insert-target').forEach(entry => {
            entry.addEventListener('click', () => {
                const field = document.getElementById(entry.dataset.target);
                const lines = boundaryLines(entry.dataset.target);
                if (!lines.includes(entry.dataset.value)) {
                    lines.push(entry.dataset.value);
                    field.value = lines.join('\n');
                    schedulePreview();
                }
                entry.classList.add('disabled');
            });
        });
    });
});


/* ------------------------------------------------------------------------
 * Role mappings.
 *
 * A row on the table is a record: the modal edits ONE of them and the server
 * saves that one. It used to be a stack of input groups written back by a
 * single "Save mappings" carrying every row, so adding one person
 * re-submitted everybody — including whatever a half-filled row happened to
 * hold.
 *
 * The table itself is rendered by the server, which is why nothing here
 * writes markup. All this does is carry a row's two values into the form,
 * and the one option the server cannot render in advance: the role a mapping
 * names that no longer exists. That option is built with createElement and
 * textContent rather than innerHTML — a role called
 * `x</select><img src=x>` is then a name, not a tag, by construction rather
 * than by escaping.
 * --------------------------------------------------------------------- */

(function setUpMappingModal() {
    const form = document.getElementById('mappingForm');
    if (!form) return;

    const title = document.getElementById('mappingModalTitle');
    const identifier = document.getElementById('mappingIdentifier');
    const original = document.getElementById('mappingOriginal');
    const role = document.getElementById('mappingRole');

    function fill(who, chosen) {
        // Whatever the last edit added. A role that has been deleted is
        // offered only while editing the mapping that still names it —
        // left in the list, it would be choosable for everybody else.
        role.querySelectorAll('option[data-missing]').forEach(option =>
            option.remove());

        identifier.value = who;
        original.value = who;
        title.textContent = who ? 'Edit mapping' : 'Add mapping';

        const known = Array.from(role.options).some(
            option => option.value === chosen);
        if (chosen && !known) {
            const option = document.createElement('option');
            option.value = chosen;
            option.textContent = `${chosen} — no longer exists`;
            option.dataset.missing = '1';
            role.appendChild(option);
        }
        // An unknown role with no option of its own would leave the select on
        // its first entry, which is the empty one — never somebody's role.
        role.value = chosen || '';
        role.classList.toggle('is-invalid', Boolean(chosen) && !known);
    }

    document.getElementById('addMappingBtn')?.addEventListener(
        'click', () => fill('', ''));

    document.querySelectorAll('.edit-mapping').forEach(button => {
        button.addEventListener('click', () => {
            const mapping = JSON.parse(button.dataset.mapping || '{}');
            fill(mapping.who || '', mapping.role || '');
        });
    });
})();


// ---------------------------------------------------------------------------
// Checks WDash runs itself
// ---------------------------------------------------------------------------

//: Whether the check now in the modal sends anything — a header, a cookie,
//: authentication, or a stored credential. What decides whether the "forget
//: what this check sends" box is offered: a checkbox that empties a check's
//: request is not something to leave on screen where there is nothing to
//: empty.
let monitorSends = false;

/**
 * Fill the check form from a row, or clear it for a new one.
 *
 * Cleared explicitly rather than relying on the browser: a modal reused for
 * "add" after an "edit" keeps whatever was in it, and somebody creating a
 * second check would silently inherit the first one's assertions.
 */
function fillMonitor(monitor) {
    const value = (id, v) => {
        const element = document.getElementById(id);
        if (element) { element.value = v === undefined || v === null ? '' : v; }
    };
    const assertions = (monitor && monitor.assertions) || {};

    value('monitorId', monitor ? monitor.id : '');
    value('monitorName', monitor ? monitor.name : '');
    value('monitorTarget', monitor ? monitor.target : '');
    value('monitorInterval', monitor ? monitor.interval_seconds : 60);
    value('monitorTimeout', monitor ? monitor.timeout_seconds : 10);
    value('monitorStatus', (assertions.status || []).join(', '));
    value('monitorBody', assertions.body_contains || '');
    value('monitorMaxDuration', assertions.max_duration_ms || '');

    const kind = document.getElementById('monitorKind');
    if (kind) { kind.value = monitor ? monitor.kind : kind.options[0].value; }

    const enabled = document.getElementById('monitorEnabled');
    if (enabled) { enabled.checked = monitor ? !!monitor.enabled : true; }

    const assigned = new Set((monitor && monitor.agent_ids) || []);
    document.querySelectorAll('.monitor-agent').forEach(box => {
        box.checked = assigned.has(box.value);
    });

    const request = (monitor && monitor.request) || {};
    value('monitorRequestHeaders', Object.entries(request.headers || {})
        .map(([k, v]) => `${k}: ${v}`).join('\n'));
    // Names only. The values are encrypted and there is no screen that can
    // show them — printing empty ones would look like they had been lost.
    value('monitorRequestCookies', (request.cookie_names || [])
        .map(name => `${name}: `).join('\n'));
    value('monitorHeadersPresent', (assertions.headers_present || []).join('\n'));
    value('monitorHeadersMatch', Object.entries(assertions.headers_match || {})
        .map(([k, v]) => `${k}: ${v}`).join('\n'));

    // The TLS decision, shown back in full. A certificate is public — that
    // is why it lives beside the request rather than in the secret box — and
    // the one question this form has to answer is WHICH one the check trusts.
    const tls = (monitor && monitor.tls) || {};
    const expiryOnly = document.getElementById('monitorTlsExpiryOnly');
    const verify = document.getElementById('monitorTlsVerify');
    if (expiryOnly) { expiryOnly.checked = tls.mode === 'expiry_only'; }
    if (verify) { verify.checked = tls.mode !== 'expiry_only'; }
    value('monitorTlsCertificate', tls.certificate || '');
    value('monitorTlsExpectedName', tls.expected_name || '');

    // Never carried over from the last check the modal held: ticked by
    // accident it empties what a check sends, and it is offered at all only
    // where there is something to forget.
    const forget = document.getElementById('monitorForgetRequest');
    if (forget) { forget.checked = false; }
    monitorSends = !!(monitor && (monitor.has_credentials
        || Object.keys(request.headers || {}).length
        || (request.cookie_names || []).length
        || (request.auth || {}).type));

    const auth = request.auth || {};
    const authType = document.getElementById('monitorAuthType');
    if (authType) { authType.value = auth.type || ''; }
    value('monitorAuthUsername', auth.username || '');
    // Never refilled: only the hash-equivalent is stored, and an empty box
    // that keeps the stored credential is the same contract the source form
    // uses.
    value('monitorAuthPassword', '');
    value('monitorAuthToken', '');

    if (window.wdashFillSteps) {
        window.wdashFillSteps((monitor && monitor.steps) || [],
                              (monitor && monitor.secret_names) || []);
    }

    applyMonitorKind();

    const title = document.getElementById('monitorModalTitle');
    if (title) { title.textContent = monitor ? 'Edit check' : 'Add check'; }
}

/**
 * Show or hide one block of the TLS section, and disable what it holds.
 *
 * The two go together for one reason: a refusal that names a box nobody can
 * see cannot be acted on. Hiding alone leaves the value in the form and the
 * browser posts it — measured, a check whose certificate textarea had just
 * been hidden by "do not verify" still submitted the certificate and the
 * save was refused about it.
 */
function setTls(selector, hide) {
    document.querySelectorAll(selector).forEach(element => {
        element.classList.toggle('d-none', hide);
        element.querySelectorAll('input, textarea, select').forEach(field => {
            field.disabled = hide;
        });
    });
}

/**
 * Show the request and response-header fields only for http checks.
 *
 * A tcp check opens a socket. Headers and auth on one are boxes somebody
 * fills in that will never be used, and a form that accepts them teaches that
 * they work.
 */
function applyMonitorKind() {
    const kind = document.getElementById('monitorKind')?.value;
    document.querySelectorAll('[data-http-only]').forEach(element => {
        element.classList.toggle('d-none', kind !== 'http');
    });
    // A tcp check opens a socket and never sees a certificate, so it gets no
    // TLS section at all; a journey gets the decision and the certificate but
    // no expected name, because a browser matches the key it is shown
    // whatever name the certificate carries.
    const expiryOnly = document.getElementById(
        'monitorTlsExpiryOnly')?.checked;
    // Hidden AND disabled, together, always. `d-none` hides a box; it does
    // not stop the browser submitting what is in it. So ticking "do not
    // verify" over a pasted certificate posted the certificate anyway and
    // the save was refused with "Naming a certificate to trust and then not
    // verifying it are opposite instructions" — about a textarea that was no
    // longer on screen. A disabled control is not submitted, and its value
    // is still there when the block comes back.
    setTls('[data-tls]', kind === 'tcp');
    setTls('[data-tls-verify]', kind === 'tcp' || expiryOnly);
    setTls('[data-tls-name]', kind !== 'http' || expiryOnly);
    // Offered only where there is something to forget, and never for a
    // journey: its secrets are named by its steps, so forgetting one leaves
    // a step with nothing to type — which would make the escape hatch a way
    // to break a check.
    setTls('[data-forget]', !monitorSends || kind === 'browser');
    document.querySelectorAll('[data-browser-only]').forEach(element => {
        element.classList.toggle('d-none', kind !== 'browser');
    });
    // The address of a journey comes from its first step. A second box asking
    // the same question has two answers, and they drift the first time
    // somebody edits one of them.
    document.querySelectorAll('[data-not-browser]').forEach(element => {
        element.classList.toggle('d-none', kind === 'browser');
        element.querySelectorAll('[required]').forEach(input => {
            // A hidden required field blocks submission with a validation
            // message pointing at something nobody can see.
            input.disabled = (kind === 'browser');
        });
    });
    const auth = document.getElementById('monitorAuthType')?.value || '';
    document.querySelectorAll('[data-auth]').forEach(element => {
        element.classList.toggle(
            'd-none', kind !== 'http' || element.dataset.auth !== auth);
    });
}

document.getElementById('monitorKind')?.addEventListener('change', applyMonitorKind);
document.getElementById('monitorAuthType')?.addEventListener('change', applyMonitorKind);
// Both radios: the certificate boxes belong to "verify", and leaving them on
// screen under "do not verify" offers a setting that would be refused.
['monitorTlsVerify', 'monitorTlsExpiryOnly'].forEach(id => {
    document.getElementById(id)?.addEventListener('change', applyMonitorKind);
});

document.getElementById('addMonitorBtn')?.addEventListener('click', () => {
    fillMonitor(null);
});

document.querySelectorAll('.edit-monitor').forEach(button => {
    button.addEventListener('click', () => {
        let monitor = null;
        try {
            monitor = JSON.parse(button.dataset.monitor);
        } catch (e) {
            console.error('could not read the check definition', e);
            return;
        }
        fillMonitor(monitor);
        const modal = document.getElementById('monitorModal');
        if (modal && window.bootstrap) {
            window.bootstrap.Modal.getOrCreateInstance(modal).show();
        }
    });
});

/**
 * Open the tab a hash names, and every tab it sits inside.
 *
 * The tab the server sent us back to. Without it every save lands on
 * Sources and the person has to find their way back to what they just
 * changed.
 *
 * One function rather than a copy per tab. There were two of these, written
 * out for `#tab-monitors` and for `#tab-alerts`, and a third tab arriving
 * meant a third copy — which is exactly why Authentication had none and why
 * every save on it landed on Sources.
 *
 * It walks OUT from the pane it is given: Authentication holds a strip of
 * its own now, and showing `#tab-auth-local` while `#tab-auth` stays shut
 * opens nothing anybody can see. Outermost first because that is the order
 * it reads in — measured, and Bootstrap is happy either way round, so the
 * order is for whoever reads this rather than for the browser.
 *
 * @param {string} hash The URL fragment, `#tab-auth-local` and the like.
 * @returns {boolean} Whether anything was opened.
 */
function openTab(hash) {
    if (!hash || !window.bootstrap) { return false; }
    const named = document.getElementById(hash.slice(1));
    if (!named || !named.classList.contains('tab-pane')) { return false; }

    const chain = [];
    for (let pane = named; pane; pane = pane.parentElement
             ? pane.parentElement.closest('.tab-pane') : null) {
        chain.unshift(pane);
    }

    let opened = false;
    for (const pane of chain) {
        const trigger = document.querySelector(
            '[data-bs-target="#' + pane.id + '"]');
        if (!trigger) { continue; }
        window.bootstrap.Tab.getOrCreateInstance(trigger).show();
        opened = true;
    }
    return opened;
}

openTab(window.location.hash);

// A link followed from inside the page changes the fragment and loads
// nothing, so the call above never runs a second time: somebody sent
// `#tab-auth-local` while already looking at this page would watch the URL
// change and the screen not.
window.addEventListener('hashchange', () => openTab(window.location.hash));

// Timestamps as the reader's local time.
document.querySelectorAll('[data-timestamp]').forEach(element => {
    const raw = element.getAttribute('data-timestamp');
    if (!raw) { return; }
    const when = new Date(raw);
    if (!isNaN(when)) { element.textContent = when.toLocaleString(); }
});


// ---------------------------------------------------------------------------
// Alert rules
// ---------------------------------------------------------------------------

/**
 * Show only the fields the chosen rule kind uses.
 *
 * A threshold on a certificate rule is a box that does nothing — certificates
 * do not flap, so the store forces it to one — and a form that offers it
 * teaches that it works.
 */
function applyRuleKind() {
    const kind = document.getElementById('ruleKind')?.value;
    document.querySelectorAll('[data-rule]').forEach(element => {
        const kinds = (element.dataset.rule || '').split(/\s+/);
        element.classList.toggle('d-none', !kinds.includes(kind));
    });
}

document.getElementById('ruleKind')?.addEventListener('change', applyRuleKind);
applyRuleKind();



// ---------------------------------------------------------------------------
// Browser journeys
// ---------------------------------------------------------------------------

/**
 * The step editor.
 *
 * A row per step, and the fields on a row follow the verb: `Expect URL` has no
 * element to act on, `Click` has no value. Showing all three boxes for every
 * verb produces steps with a selector on an assertion that ignores it, and
 * somebody wrote it believing it narrowed the check.
 *
 * The verb list is not hard-coded here. It is rendered from the same
 * dictionary the server validates against, so a form that accepts a step
 * cannot be one the agent does not understand.
 */
(function setUpSteps() {
    const rows = document.getElementById('stepRows');
    if (!rows) return;

    const KINDS = JSON.parse(
        document.getElementById('stepKinds')?.textContent || '{}');
    const field = document.getElementById('stepsField');
    const secretRows = document.getElementById('secretRows');

    function serialise() {
        const steps = [];
        rows.querySelectorAll('.step-row').forEach(row => {
            const kind = row.querySelector('.step-kind').value;
            const spec = KINDS[kind] || {};
            const step = {kind: kind};
            if (spec.selector) {
                step.selector = row.querySelector('.step-selector').value.trim();
            }
            if (spec.value) {
                step.value = row.querySelector('.step-value').value.trim();
            }
            steps.push(step);
        });
        field.value = JSON.stringify(steps);
        renumber();
        showSecrets(steps);
    }

    function renumber() {
        rows.querySelectorAll('.step-row').forEach((row, index) => {
            row.querySelector('.step-number').textContent = index + 1;
        });
    }

    /**
     * A box for every `{{ secret.name }}` the steps mention.
     *
     * Driven by the steps rather than kept as its own list: a credential that
     * outlives the step that used it is a credential nobody knows is there.
     * Existing values are never refilled — only whether one is stored.
     */
    function showSecrets(steps) {
        if (!secretRows) return;
        const wanted = [];
        steps.forEach(step => {
            const matches = String(step.value || '')
                .matchAll(/\{\{\s*secret\.([A-Za-z0-9_-]{1,64})\s*\}\}/g);
            for (const match of matches) {
                if (!wanted.includes(match[1])) wanted.push(match[1]);
            }
        });

        const known = new Set();
        secretRows.querySelectorAll('input').forEach(input => {
            if (wanted.includes(input.dataset.secret)) {
                known.add(input.dataset.secret);
            } else {
                input.parentElement.remove();
            }
        });
        const stored = new Set(JSON.parse(
            document.getElementById('stepsField').dataset.stored || '[]'));
        wanted.filter(name => !known.has(name)).forEach(name => {
            const group = document.createElement('div');
            group.className = 'input-group input-group-sm mb-1';
            group.innerHTML =
                `<span class="input-group-text" style="min-width:9rem">${
                    escapeHtml(name)}</span>
                 <input type="password" class="form-control"
                        name="journey_secret_${escapeHtml(name)}"
                        data-secret="${escapeHtml(name)}" autocomplete="off"
                        placeholder="${stored.has(name)
                            ? 'stored — leave empty to keep it'
                            : 'required'}">`;
            secretRows.appendChild(group);
        });
        document.getElementById('journeySecrets')
            ?.classList.toggle('d-none', wanted.length === 0);
    }

    function applyRow(row) {
        const spec = KINDS[row.querySelector('.step-kind').value] || {};
        const selector = row.querySelector('.step-selector');
        const value = row.querySelector('.step-value');
        selector.classList.toggle('d-none', !spec.selector);
        value.classList.toggle('d-none', !spec.value);
        value.placeholder = spec.value_label || '';
        row.querySelector('.step-hint').textContent = spec.hint || '';
    }

    function addRow(step) {
        step = step || {};
        const row = document.createElement('div');
        row.className = 'mb-2 step-row';
        row.innerHTML =
            `<div class="input-group input-group-sm">
               <span class="input-group-text step-number"
                     style="min-width:2.2rem; justify-content:center"></span>
               <select class="form-select step-kind" style="max-width:11rem">
                 ${Object.entries(KINDS).map(([name, spec]) =>
                     `<option value="${name}"${
                         name === step.kind ? ' selected' : ''}>${
                         escapeHtml(spec.label)}</option>`).join('')}
               </select>
               <input type="text" class="form-control step-selector"
                      placeholder="#email" value="${
                          escapeHtml(step.selector || '')}">
               <input type="text" class="form-control step-value" value="${
                          escapeHtml(step.value || '')}">
               <button type="button" class="btn btn-outline-secondary step-up"
                       title="Move up">&uarr;</button>
               <button type="button" class="btn btn-outline-secondary step-down"
                       title="Move down">&darr;</button>
               <button type="button" class="btn btn-outline-danger step-remove"
                       title="Remove">&times;</button>
             </div>
             <div class="form-text step-hint" style="font-size:.7rem"></div>`;
        rows.appendChild(row);

        row.querySelector('.step-remove').addEventListener('click', () => {
            row.remove();
            serialise();
        });
        // Order is the whole meaning of a journey, and rewriting three rows to
        // move one step is how somebody ends up with a sign-in after the
        // checkout.
        row.querySelector('.step-up').addEventListener('click', () => {
            const previous = row.previousElementSibling;
            if (previous) rows.insertBefore(row, previous);
            serialise();
        });
        row.querySelector('.step-down').addEventListener('click', () => {
            const next = row.nextElementSibling;
            if (next) rows.insertBefore(next, row);
            serialise();
        });
        row.querySelector('.step-kind').addEventListener('change', () => {
            applyRow(row);
            serialise();
        });
        row.querySelectorAll('input').forEach(input => {
            input.addEventListener('input', serialise);
        });
        applyRow(row);
        serialise();
    }

    document.getElementById('addStepRow')?.addEventListener('click',
                                                             () => addRow());
    window.wdashFillSteps = function (steps, storedSecrets) {
        rows.innerHTML = '';
        if (secretRows) secretRows.innerHTML = '';
        field.dataset.stored = JSON.stringify(storedSecrets || []);
        (steps || []).forEach(addRow);
        // A new journey starts with the one step every journey must have,
        // rather than an empty box and an error on save.
        if (!(steps || []).length) addRow({kind: 'goto'});
        serialise();
    };
})();
