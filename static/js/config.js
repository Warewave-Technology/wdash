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
                  result.details.replace(/[&<>]/g, c =>
                      ({'&': '&amp;', '<': '&lt;', '>': '&gt;'}[c]))}</div>`
            : '';
        target.innerHTML = `<div class="alert alert-${tone} py-2 mb-0">` +
            `<i class="fas fa-${icon}"></i> ${result.message || result.error}${detail}</div>`;
    } catch (error) {
        target.innerHTML = '<div class="alert alert-danger py-2 mb-0">' +
            'The test could not be run: ' + error.message + '</div>';
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

document.getElementById('addRoleBtn')?.addEventListener('click', () => fillRole(null));

document.querySelectorAll('.edit-role').forEach(button => {
    button.addEventListener('click', () => fillRole(JSON.parse(button.dataset.role)));
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

    const change = result.change;
    if (change && (change.logs_added.length || change.logs_removed.length ||
                   change.traces_added.length || change.traces_removed.length ||
                   change.permissions_added.length ||
                   change.permissions_removed.length)) {
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
function renderChange(change) {
    const list = (label, items, tone) => items.length
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
        list('grants permissions:', change.permissions_added, 'text-warning') +
        list('removes permissions:', change.permissions_removed, 'text-muted') +
        '</div>';
}

document.querySelectorAll('.boundary-field').forEach(field => {
    field.addEventListener('input', schedulePreview);
});
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
            body.innerHTML = available.services.length
                ? available.services.map(name =>
                    `<button type="button" class="btn btn-sm btn-outline-secondary me-1 mb-1 insert-target"
                             data-target="${targetId}" data-value="${escapeHtml(name)}">
                       ${escapeHtml(name)}</button>`).join('')
                : '<div class="text-muted">No services seen in the last 24 hours.</div>';
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
                    // Strip a trailing rotation suffix to suggest a pattern
                    // that survives the next roll-over.
                    const suggested = name.replace(/[-.]\d{4,}$/, '') + '*';
                    return `<tr>
                      <td><code style="font-size:.78rem">${escapeHtml(name)}</code></td>
                      <td class="text-end text-nowrap">
                        <button type="button" class="btn btn-sm btn-outline-primary insert-target"
                                data-target="${targetId}" data-value="${escapeHtml(suggested)}"
                                title="Survives rotation">${escapeHtml(suggested)}</button>
                        <button type="button" class="btn btn-sm btn-outline-secondary insert-target"
                                data-target="${targetId}" data-value="${escapeHtml(name)}"
                                title="Pins the role to this exact container">exact</button>
                      </td></tr>`;
                }).join('');
                return `<div class="mb-3"><strong>${escapeHtml(entry.source)}</strong>
                        <table class="table table-sm table-dark mb-0">${rows}</table></div>`;
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
 * The identifier stays free text — an email or username cannot be enumerated
 * from here, and guessing at a list would be worse than a box. The ROLE is
 * chosen, because a role name that does not exist grants nothing and looks
 * configured, which is the same failure the permission catalogue exists to
 * prevent.
 *
 * Serialised back into the one-per-line form the server already parses and
 * re-validates, so the form is a convenience over the contract rather than a
 * second contract.
 * --------------------------------------------------------------------- */

(function setUpMappings() {
    const rows = document.getElementById('mappingRows');
    if (!rows) return;

    const roleNames = JSON.parse(
        document.getElementById('roleNames')?.textContent || '[]');
    const existing = JSON.parse(
        document.getElementById('mappingData')?.textContent || '{}');

    function serialise() {
        const lines = [];
        rows.querySelectorAll('.mapping-row').forEach(row => {
            const who = row.querySelector('.mapping-who').value.trim();
            const role = row.querySelector('.mapping-role').value;
            if (who) lines.push(`${who} = ${role}`);
        });
        document.getElementById('mappingField').value = lines.join('\n');
    }

    function addRow(who = '', role = '') {
        const row = document.createElement('div');
        row.className = 'input-group input-group-sm mb-1 mapping-row';
        row.innerHTML =
            `<input type="text" class="form-control mapping-who"
                    placeholder="alice@example.com" value="${
                        String(who).replace(/"/g, '&quot;')}">
             <span class="input-group-text">is</span>
             <select class="form-select mapping-role" style="max-width:11rem">
               ${roleNames.map(name =>
                   `<option value="${name}"${name === role ? ' selected' : ''}>${
                       name}</option>`).join('')}
             </select>
             <button type="button" class="btn btn-outline-danger mapping-remove"
                     title="Remove">&times;</button>`;
        rows.appendChild(row);

        row.querySelector('.mapping-remove').addEventListener('click', () => {
            row.remove();
            serialise();
        });
        row.querySelectorAll('input, select').forEach(field => {
            field.addEventListener('input', serialise);
            field.addEventListener('change', serialise);
        });
        serialise();
    }

    Object.entries(existing).forEach(([who, role]) => addRow(who, role));
    document.getElementById('addMappingRow')?.addEventListener('click',
                                                               () => addRow());
    serialise();
})();
