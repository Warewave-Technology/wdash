/**
 * Dashboard loader.
 *
 * Every panel is fed from a SINGLE request: /api/dashboard/<id>/data
 *
 * Each panel used to call its own endpoint — five HTTP requests and five
 * separate Elasticsearch queries on the server. The query is identical in all
 * of them; only the aggregations differ, and the server now produces all four
 * from one Elasticsearch request. Five HTTP + five ES round trips became one
 * and one.
 *
 * The per-panel endpoints (stats, timeline, log-levels, services, heatmap)
 * still exist on the server; this UI no longer calls them.
 */

/**
 * A colour from the palette, by token name.
 *
 * Read at call time rather than cached at load: the palette is what a theme
 * overrides, and a value captured once would be whichever theme happened to
 * be active when the page opened.
 *
 * Written out in both scripts rather than shared. There is no module system
 * here and the load order between them is decided by template blocks, so a
 * helper that arrives second is a helper that is undefined the first time it
 * is wanted. Five lines twice beats a race.
 *
 * No fallback colour on purpose: a fallback is a literal, and a literal is
 * the thing being removed. If a token is missing the value comes back empty
 * and the chart draws in its own default, which is visible — and
 * `tests/test_contrast.py` fails, because every token named here has to
 * exist in `:root`.
 */
function paletteColour(name) {
    return getComputedStyle(document.documentElement)
        .getPropertyValue(name).trim();
}


/**
 * Which raw level names each stat card stands for.
 *
 * The authority is the server's `LEVEL_GROUPS` (api/dashboard_routes.py),
 * which ships the finished query with every response; this is what a click
 * made before the first response has landed falls back to, and it must say
 * the same thing. `tests/test_dashboard_contract.py` compares the two.
 */
const LEVEL_GROUPS = {
    error: ['ERROR', 'FATAL'],
    warn: ['WARN', 'WARNING'],
    info: ['INFO'],
};


/**
 * What clicking inside a panel actually does, by panel type.
 *
 * The hint used to be one ternary: 'Click a segment to open those records'
 * for a timeseries and 'Click a value to filter by it' for EVERYTHING else.
 * Nothing filters. A terms click opens the Logs page in a new tab and a
 * trace-services click opens the Traces page in one — so the sentence under
 * a Top Services card promised a behaviour this dashboard has never had,
 * and the existing trace panel wore it too.
 *
 * A TABLE, not a default: a panel type that is not named here says nothing,
 * because the honest hint for a panel whose click does nothing yet is no
 * hint at all. A new panel type inherits silence and adds its own line when
 * it has a click to describe — which is the opposite of what the ternary
 * did, where every type added inherited the promise.
 *
 * With NO PROTOTYPE, so that "not named here" means what it says. A plain
 * object literal answers `constructor`, `toString` and `valueOf` with an
 * inherited function, and this lookup is `PANEL_HINTS[panel.type] || ''` —
 * so a panel of one of those types would have set the hint to a function
 * and printed `function Object() { [native code] }` into the card header.
 * Unreachable today, because `PANEL_TYPES` refuses a kind it does not name
 * and the route answers 400 for the whole board; reachable by whoever adds
 * the next panel type, which is what this table is for.
 */
const PANEL_HINTS = Object.assign(Object.create(null), {
    timeseries: 'Click a segment to open those records in the Logs page',
    terms: 'Click a value to open those records in the Logs page',
    // Not a click. This panel exists so that reading the records does not
    // cost the board, so a hint promising somewhere to go would be the same
    // untrue sentence the other way round.
    records: 'The newest records this board matches, on the board',
    // Not a click either, and the caption under the number says what was
    // counted — a number whose question is only in the author's title is a
    // number nobody else can check.
    count: 'One value of one field, counted over this window',
    // Not a click either, and — unlike every panel above — not narrowed by
    // the board. These read WDash's own store, so the board's stored query
    // and the ad-hoc ?q= reach them no more than they reach the Monitors
    // page. On a board filtered to one service the charts beside them narrow
    // and these do not, and two panels side by side are read as one picture
    // unless one of them says otherwise. No semicolon in either of these:
    // tests/test_dashboard_tables.py reads this table with a regex that
    // stops at the first one, and a hint carrying one takes the whole table
    // out of its reach.
    alerts: 'Every rule on this instance, in this window — the board’s '
            + 'filter does not reach alert history',
    alerts_undelivered: 'The last word on each rule and subject, counted as '
                        + 'the Alerts page counts it — the board’s filter '
                        + 'does not reach alert history',
    trace_services: 'Click a service to open it in the Traces page',
    trace_list: 'Click a trace to open its waterfall in this window',
    monitors: 'Click a check to open it in the Monitors page',
    monitor_certificates: 'One row per certificate. Click a check to open it in the Monitors page',
});


/**
 * How often auto-refresh asks, in seconds, when the page offers no choice.
 *
 * It was one hardcoded 30000 inside `setInterval`, tuned for the backend
 * where a refresh is cheap. One refresh of a board is ONE request on
 * Elasticsearch however many panels it has, because every log panel rides a
 * single msearch; on Loki and VictoriaLogs the adapter issues one request per
 * panel plus two for the stat cards, so an eight-panel board is ten — per
 * source it reads, per open tab, every interval. A board over all sources
 * reads every one: measured against the lab, 1 + 10 + 10.
 */
const DEFAULT_REFRESH_SECONDS = 30;


/**
 * A UTC instant as a `datetime-local` input's value, in the reader's own zone.
 *
 * The URL carries UTC, because a shared link must mean the same window to
 * whoever opens it; the boxes show local time, because "last Tuesday 14:00"
 * is a local sentence. `new Date(value)` parses a bare `datetime-local` as
 * local, so the conversion back is the constructor's own.
 */
function localInputValue(iso) {
    const at = new Date(iso);
    if (isNaN(at.getTime())) return '';
    const p = n => String(n).padStart(2, '0');
    return `${at.getFullYear()}-${p(at.getMonth() + 1)}-${p(at.getDate())}`
         + `T${p(at.getHours())}:${p(at.getMinutes())}`;
}


/** Text into HTML. One definition: it was written inside drawServiceTable,
 *  and every panel that renders markup needs the same one. */
function escapeHtml(value) {
    return String(value == null ? '' : value).replace(/[&<>"]/g,
        c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}


/**
 * A monitor's own page. Mirrors MonitorIdConverter.to_url, because the ids
 * come from the documents and a link built with encodeURIComponent alone
 * still resolves against its neighbours: `.` and `..` are dot segments
 * however they are encoded, so an id of `..` linked to the home page.
 *
 * Down to the last character, on purpose. `encodeURIComponent` leaves
 * ! ' ( ) * bare where Python's `quote(safe="")` percent-encodes them;
 * nothing routes differently for those five, but a copy of a rule that
 * agrees only approximately is a copy nobody can check, and the next
 * character to diverge may be one that does matter. The two are held to one
 * list of ids by MonitorLinkTest and the jsdom check of the same name.
 */
function monitorUrl(id) {
    let text = String(id == null ? '' : id).replace(/~/g, '~7E');
    if (text === '.' || text === '..') text = '~' + text;
    return `/monitors/${encodeURIComponent(text).replace(
        /[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())}`;
}


/**
 * A chart value as a quoted string in the query language. Bucket keys are
 * whatever a log writer put in the document, and they went into the Logs
 * query between quotes with nothing escaped — a level of
 * `x OR service:hr-salaries` clicked on the Payments dashboard showed every
 * hr-salaries record as that slice of it.
 */
function quoted(value) {
    return '"' + String(value == null ? '' : value)
        .replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

/**
 * The kinds of error where the log half did not answer at all.
 *
 * A board whose log source is down answers 200 now, so that the panels that
 * CAN answer are drawn — and the page-level sentence, which used to arrive
 * through `showLoadError` in red, arrived through the success arm in yellow
 * instead. The cards say why they are empty either way, so this was never a
 * lie; it read like a caveat rather than an outage, which is not what a
 * backend that never answered is.
 *
 * The two kinds deliberately NOT here are answers: `no_accessible_containers`
 * means the scope really does reach none of the dashboard's indices, and
 * `invalid_query` means the filter really is a typo. Both keep the caution
 * tone they have always had.
 */
const BACKEND_FAILURES = Object.assign(Object.create(null), {
    elasticsearch_connection: true,
    source_missing: true,
    query_failed: true,
});

/** How loudly to say what came back with the data. */
function messageTone(data) {
    if (!data.error) return 'info';
    return BACKEND_FAILURES[data.error_type] ? 'danger' : 'warning';
}

/** Bare when the parser reads it as itself, quoted otherwise. Levels were
 *  written bare, and a bare level stays what it was. */
function queryValue(value) {
    const text = String(value == null ? '' : value);
    return /^[A-Za-z0-9_.@][A-Za-z0-9_.@-]*$/.test(text) && !/^(and|or|not)$/i.test(text)
        ? text : quoted(text);
}

class AsyncDashboard {
    constructor(dashboardId, dashboardQuery) {
        this.dashboardId = dashboardId;
        // Carried into every click-through, along with the dashboard's id:
        // the query narrows what is asked, and the id is what narrows WHERE
        // it is asked — the containers the dashboard's patterns resolve to.
        // Without the id the Logs screen answered from the whole scope.
        this.dashboardQuery = dashboardQuery || '*';
        this.lastData = null;
        this.charts = {};
        this.autoRefreshInterval = null;
        this.isAutoRefreshing = false;
        this.loading = false;
        //: A load asked for while one was running, to be run when it ends.
        this.pending = null;


        this.init();
    }

    init() {
        console.log('🚀 Initializing Async Dashboard:', this.dashboardId);
        this.applyUrlState();
        this.setupEventListeners();
        // After the URL has been read, so a link that arrives saying "off"
        // arrives with the button already unavailable rather than offering a
        // rate nobody chose.
        this.applyRefreshChoice();
        this.initializeCharts();
        this.setupStatCards();

        // Every chart is painted with the colours of the moment it was drawn.
        // On a theme switch they are thrown away and drawn again from the
        // answer already on the page: Chart.js restyling in place keeps the
        // old defaults, and asking the backend again would be a query for a
        // colour change.
        document.addEventListener('wdash:theme', () => {
            this.initializeCharts();
            Object.values(this.charts).forEach(chart => chart.destroy());
            this.charts = {};
            if (this.lastData) this.render(this.lastData);
        });

        // Start progressive loading immediately
        this.load();
    }

    /**
     * Restore time range and filter from the query string.
     *
     * Without this a dashboard link is only "the dashboard" — the recipient
     * lands on the default hour with no filter and has to be told, in prose,
     * what to select. What is worth sharing is the view, not the page.
     */
    applyUrlState() {
        const params = new URLSearchParams(window.location.search);
        const select = document.getElementById('timeRange');

        // An absolute range wins over a relative one when both are in the
        // link: `start`/`end` name a window, `time_range` names a rule for
        // making one, and a link carrying both was written by something that
        // did not decide.
        const start = params.get('start');
        const end = params.get('end');
        const from = document.getElementById('rangeStart');
        const to = document.getElementById('rangeEnd');
        if (start && end && select && from && to) {
            select.value = 'custom';
            from.value = localInputValue(start);
            to.value = localInputValue(end);
        } else {
            const timeRange = params.get('time_range');
            if (timeRange && select
                && [...select.options].some(o => o.value === timeRange)) {
                select.value = timeRange;
            }
        }
        this.showRangeInputs();

        const refresh = params.get('refresh');
        const interval = document.getElementById('refreshInterval');
        if (refresh && interval
            && [...interval.options].some(o => o.value === refresh)) {
            interval.value = refresh;
        }

        const filter = params.get('q');
        const input = document.getElementById('dashboardFilter');
        if (filter && input) input.value = filter;
    }

    /** Show the two boxes only when they are the range being used. */
    showRangeInputs() {
        const row = document.getElementById('customRange');
        if (!row) return;
        row.classList.toggle('d-none', !this.isAbsolute());
    }

    /**
     * Whether the picker is on the absolute range at all.
     *
     * Said once, because four things now turn on it — which boxes are shown,
     * which parameters are asked for, what goes in the address bar, and
     * whether this tab keeps querying at all: a window with both ends fixed
     * cannot produce a different answer however often it is asked.
     */
    isAbsolute() {
        return document.getElementById('timeRange')?.value === 'custom';
    }

    /**
     * The absolute window the two boxes name, in UTC — or null.
     *
     * Null for every relative range, and null for an absolute one that is not
     * yet usable. `load` refuses to ask in the second case rather than
     * falling back to the default hour: an hour of data under a control
     * reading "Between two times" is the failure this product refuses
     * everywhere else, emptiness — or worse, plausible numbers — standing in
     * for a question nobody asked.
     */
    absoluteBounds() {
        if (!this.isAbsolute()) return null;
        const from = document.getElementById('rangeStart')?.value || '';
        const to = document.getElementById('rangeEnd')?.value || '';
        if (!from || !to) return null;
        const start = new Date(from);
        const end = new Date(to);
        if (isNaN(start.getTime()) || isNaN(end.getTime()) || end <= start) {
            return null;
        }
        return { start: start.toISOString(), end: end.toISOString() };
    }

    /** Why the chosen range cannot be asked for, or '' when it can. */
    rangeProblem() {
        if (!this.isAbsolute()) return '';
        if (this.absoluteBounds()) return '';
        const from = document.getElementById('rangeStart')?.value || '';
        const to = document.getElementById('rangeEnd')?.value || '';
        if (!from || !to) return 'Choose both a start and an end.';
        return 'The start of a range must be before its end.';
    }

    /** How often auto-refresh should ask, in seconds. 0 is off. */
    refreshSeconds() {
        const select = document.getElementById('refreshInterval');
        if (!select) return DEFAULT_REFRESH_SECONDS;
        const seconds = Number(select.value);
        return Number.isFinite(seconds) && seconds > 0 ? seconds : 0;
    }

    /**
     * Keep the address bar in step with the controls.
     *
     * replaceState rather than pushState: changing the time range is adjusting
     * the current view, not navigating, and filling the back button with every
     * intermediate selection makes leaving the page take ten presses.
     */
    syncUrl() {
        const params = new URLSearchParams();
        const bounds = this.absoluteBounds();
        if (bounds) {
            // The bounds and NOT `time_range` beside them: two answers to one
            // question, and the recipient's page would have to pick.
            params.set('start', bounds.start);
            params.set('end', bounds.end);
        } else if (!this.isAbsolute()) {
            params.set('time_range',
                       document.getElementById('timeRange')?.value || '1h');
        } else {
            // "custom" is the NAME of a control, not a window, and this used
            // to write it into the address bar the moment the picker moved —
            // where the Share button copies it. The server read it as a range
            // it could not parse and answered the default hour, so a link
            // copied mid-edit opened on an hour nobody had chosen. Whatever
            // window the link already named is kept until the two boxes name
            // a new one: half a window is not a view to share.
            const already = new URLSearchParams(window.location.search);
            ['start', 'end', 'time_range'].forEach(key => {
                if (already.has(key)) params.set(key, already.get(key));
            });
        }

        const filter = (document.getElementById('dashboardFilter')?.value || '').trim();
        if (filter) params.set('q', filter);

        // Carried like the time range, and for the same reason: a link to a
        // board somebody is watching should arrive watching.
        const interval = document.getElementById('refreshInterval');
        if (interval) params.set('refresh', interval.value);

        window.history.replaceState(null, '',
            `${window.location.pathname}?${params.toString()}`);
    }

    setupEventListeners() {
        const refreshBtn = document.getElementById('refreshBtn');
        const timeRange = document.getElementById('timeRange');
        const autoRefreshBtn = document.getElementById('autoRefreshBtn');

        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.load());
        }

        if (timeRange) {
            timeRange.addEventListener('change', () => {
                this.showRangeInputs();
                this.syncUrl();
                // Which window is being asked decides whether asking again
                // can change the answer, so the refresh control follows the
                // picker rather than waiting for somebody to touch it.
                this.applyRefreshChoice();
                this.load();
            });
        }

        // Both boxes, so filling the second one asks. Filling only the first
        // asks too, and is refused by name — see `load`.
        ['rangeStart', 'rangeEnd'].forEach(id => {
            const box = document.getElementById(id);
            if (box) {
                box.addEventListener('change', () => { this.syncUrl(); this.load(); });
            }
        });

        const interval = document.getElementById('refreshInterval');
        if (interval) {
            // No load: choosing how often to ask is not asking. It restarts a
            // running timer at the new rate, which is what changing it while
            // watching is for.
            interval.addEventListener('change', () => {
                this.syncUrl();
                this.applyRefreshChoice();
            });
        }

        const filter = document.getElementById('dashboardFilter');
        if (filter) {
            // Enter rather than keystroke-debounce: a half-typed field name is
            // a parse error, and firing a query on every character turns one
            // filter into a dozen rejected requests.
            filter.addEventListener('keydown', e => {
                if (e.key === 'Enter') { e.preventDefault(); this.syncUrl(); this.load(); }
            });
        }

        const clearFilter = document.getElementById('clearFilterBtn');
        if (clearFilter) {
            clearFilter.addEventListener('click', () => {
                if (filter) filter.value = '';
                this.syncUrl();
                this.load();
            });
        }

        const share = document.getElementById('shareBtn');
        if (share) {
            share.addEventListener('click', () => this.copyLink(share));
        }

        if (autoRefreshBtn) {
            autoRefreshBtn.addEventListener('click', () => this.toggleAutoRefresh());
        }

        // Coming back to a paused tab should show current data immediately
        // rather than up to thirty seconds of staleness.
        document.addEventListener('visibilitychange', () => {
            if (this.isAutoRefreshing && document.visibilityState === 'visible') {
                this.load({ quiet: true });
            }
        });
    }

    /**
     * Load dashboard data and render the panels.
     */
    /**
     * @param {boolean} quiet  A background refresh rather than a user action.
     *
     * A quiet load leaves the numbers on screen and says nothing when it
     * succeeds. Blanking every panel to a spinner every thirty seconds makes a
     * dashboard people watch unreadable, and a success toast on a timer trains
     * everyone to ignore toasts — including the one that matters.
     */
    async load({ quiet = false } = {}) {
        // A change made while a load is running is QUEUED, not dropped.
        //
        // It used to return here and leave nothing behind. The handlers for
        // the time range, the filter and the clear button all call syncUrl()
        // and then load(), so a change made during a load moved the select,
        // moved the address bar, and then never asked: the page showed the
        // last hour's answer under a control reading "24 hours", the URL said
        // ?time_range=24h, and a green "loaded" toast said it had worked.
        if (this.loading) {
            this.pending = this.pending || {};
            // The queued load is a user action unless every request that
            // arrived while this one ran was a background refresh.
            this.pending.quiet = Boolean(this.pending.quiet ?? true) && quiet;
            return;
        }

        // Half an absolute range is not a window, and it is not the default
        // hour either. Refused HERE, before anything spins or is blanked, and
        // said in words: falling through would have asked for the last hour
        // and drawn it under a control reading "Between two times", which is
        // a real answer to a question nobody asked — the worst of the three
        // things this page can do.
        const problem = this.rangeProblem();
        if (problem) {
            // And the board goes with it. Refusing while leaving the previous
            // window's numbers and charts on screen is the same failure said
            // twice: a page of real figures under a control reading "Between
            // two times", sourced from the last answer rather than from any
            // question now being asked. Measured before this line: switching
            // the picker to the absolute range left totalHits at 4,311 and
            // three charts drawn, with a one-line banner above them.
            this.clearBoard();
            this.showMessage(problem, [], 'warning');
            return;
        }

        this.loading = true;

        if (!quiet) this.showAllLoadingStates();

        const lastUpdatedEl = document.getElementById('lastUpdated');
        if (lastUpdatedEl && !quiet) lastUpdatedEl.textContent = 'Loading...';

        try {
            const data = await this.loadAll();

            // With no accessible indices the server returns empty data plus
            // an explanation, and a partial answer returns data plus
            // warnings. Neither is an error, and both need saying — on the
            // page, which is where the reader is looking.
            this.render(data);
            this.showMessage(data.error || '', data.warnings,
                             messageTone(data));

            if (lastUpdatedEl && !this.pending) {
                lastUpdatedEl.textContent = new Date().toLocaleString();
            }
        } catch (error) {
            console.error('Dashboard load failed:', error);
            if (lastUpdatedEl) lastUpdatedEl.textContent = 'Failed to load';
            this.showLoadError(error.message || 'Failed to load dashboard',
                               error.payload);
        } finally {
            this.loading = false;
            const queued = this.pending;
            this.pending = null;
            // Run the newest request, and only the newest: the controls hold
            // one state, so several changes made during one load all ask for
            // the same thing.
            if (queued) await this.load(queued);
        }
    }

    /**
     * Take every answer off the screen, because none of them is one any more.
     *
     * The counts go to the same em dash a count that did not run gets — "we
     * did not ask", which is exactly true — rather than to zero, which would
     * be the loudest possible lie. The panels are removed rather than left
     * spinning: nothing is loading, and a spinner would promise an answer
     * that is not coming until the control names a window.
     */
    clearBoard() {
        this.updateStats({});
        this.renderWindow(null);
        Object.values(this.charts).forEach(chart => chart.destroy());
        this.charts = {};
        document.querySelectorAll('.panel-slot').forEach(slot => slot.remove());
        document.querySelector('#panelGrid .grid-loading')?.remove();
        // So a drill-down cannot carry the filter of a window nobody is
        // looking at any more; `openLogs` falls back to the stored query.
        this.lastData = null;
    }

    showAllLoadingStates() {
        ['totalHits', 'errorCount', 'warnCount', 'infoCount'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = '<div class="spinner-border spinner-border-sm"></div>';
        });

        // Panels that already exist get an overlay. On the very first load
        // there are none yet — the grid is built from the response — so the
        // grid itself shows the spinner.
        const slots = document.querySelectorAll('.panel-slot');
        if (!slots.length) {
            const grid = document.getElementById('panelGrid');
            if (grid && !grid.querySelector('.grid-loading')) {
                grid.innerHTML =
                    '<div class="col-12 text-center py-5 text-muted grid-loading">' +
                    '<div class="spinner-border text-primary"></div>' +
                    '<div class="mt-2"><small>Loading panels…</small></div></div>';
            }
            return;
        }
        slots.forEach(slot => this.addPanelOverlay(slot));
    }

    addPanelOverlay(slot) {
        const container = slot.querySelector('.chart-container');
        if (!container || container.querySelector('.chart-loading-overlay')) return;
        container.style.position = 'relative';

        const overlay = document.createElement('div');
        overlay.className = 'chart-loading-overlay';
        overlay.innerHTML =
            '<div class="spinner-border text-primary" role="status">' +
            '<span class="visually-hidden">Loading...</span></div>';
        container.appendChild(overlay);
    }

    removePanelOverlay(slot) {
        slot.querySelector('.chart-loading-overlay')?.remove();
        document.querySelector('#panelGrid .grid-loading')?.remove();
    }

    /**
     * Fetch all panel data in one request.
     */
    async loadAll() {
        const response = await fetch(
            `/api/dashboard/${this.dashboardId}/data?${this.getQueryParams()}`);
        const data = await response.json();

        if (!response.ok) {
            const failure = new Error(data.error || `HTTP ${response.status}`);
            // The body says more than the sentence does — the warnings behind
            // a refused query, for one — and it was thrown away here.
            failure.payload = data;
            throw failure;
        }
        return data;
    }

    /**
     * Draw every panel from a single response.
     *
     * Each panel sits in its own try block so a rendering failure in one chart
     * does not take the others down. A network failure now drops all of them
     * together, which is inherent to the single request — but a drawing error
     * must not spread.
     */
    render(data) {
        this.lastData = data;
        document.getElementById('dashboardFilter')?.classList.remove('is-invalid');

        try {
            this.updateStats(data);
            this.renderWindow(data.window);
        } catch (error) {
            console.error('Stat render error:', error);
        }

        (data.panels || []).forEach(panel => {
            try {
                this.renderPanel(panel);
            } catch (error) {
                console.error(`Panel render error (${panel.title}):`, error);
                this.panelMessage(panel.id, 'This panel could not be drawn.');
            }
        });

        // Charts for panels that no longer exist would otherwise sit there
        // holding a canvas and a Chart.js instance for ever.
        const live = new Set((data.panels || []).map(p => p.id));
        Object.keys(this.charts).forEach(id => {
            if (!live.has(id)) {
                this.charts[id].destroy();
                delete this.charts[id];
                document.querySelector(`[data-panel-id="${id}"]`)?.remove();
            }
        });

        this.stopSpinning();
    }

    /**
     * Nothing is loading once a render has finished. Make that true.
     *
     * The removal used to sit at the end of `renderPanel`, on a line that
     * three early returns skipped — no data in the window, a panel whose
     * source failed, a chart that would not draw. So the three cases that
     * most needed explaining were the three that kept spinning instead, and
     * choosing a time range with no logs in it left the whole dashboard
     * loading for ever.
     *
     * Stating the invariant once beats fixing the three paths: the response
     * is in and drawn, so a spinner left ANYWHERE is a lie about the state,
     * whichever branch left it — including one added later.
     *
     * It also covers the case with no panels at all — a dashboard with none
     * configured, or a response that carried an explanation instead — where
     * there is no slot for a per-panel removal to be reached through.
     */
    stopSpinning() {
        document.querySelectorAll(
            '#panelGrid .grid-loading, .chart-loading-overlay'
        ).forEach(element => element.remove());
    }

    /**
     * The card a panel lives in, created on first sight.
     *
     * Reused across refreshes rather than rebuilt: replacing the DOM every
     * thirty seconds would destroy and re-create a Chart.js instance per panel
     * and make the whole page flash.
     */
    panelSlot(panel) {
        const grid = document.getElementById('panelGrid');
        if (!grid) return null;

        let slot = grid.querySelector(`[data-panel-id="${panel.id}"]`);
        if (!slot) {
            const template = document.getElementById('panelTemplate');
            slot = template.content.firstElementChild.cloneNode(true);
            slot.dataset.panelId = panel.id;
            grid.appendChild(slot);
        }

        slot.className = `col-md-${panel.width} panel-slot`;
        slot.dataset.panelId = panel.id;
        // How tall, beside how wide, from the panel itself. The card template
        // used to say `height:300px` for every panel on every board, so a
        // one-row service table left two thirds of its card empty and a
        // twenty-row table scrolled inside a box. `normalise` clamps the
        // number and gives one to every panel, including the ones stored
        // before this existed, so there is nothing to default to here.
        slot.querySelector('.chart-container').style.height = `${panel.height}px`;
        slot.querySelector('.panel-title').textContent = panel.title;

        // A panel whose source answered for only some of its backends says so
        // where its numbers are. It used to draw the rows it got and nothing
        // else, so a trace store that did not reply looked like a service
        // that had gone quiet — which is the one reading this panel exists to
        // support.
        const hint = slot.querySelector('.panel-hint');
        const notes = (panel.warnings || []).filter(Boolean);
        // Only where there are numbers for it to qualify. A panel with
        // nothing to draw prints its reason where the chart would be
        // (`renderPanel`, `drawServiceTable`), and a header saying the same
        // sentence two lines above that is one fact twice in one card —
        // which is what an unanswerable Elasticsearch panel looked like.
        // The same test `renderPanel` makes before it prints the reason
        // instead of a chart, so the two cannot drift into saying it twice
        // or into saying it nowhere: an all-zero series draws no chart
        // either.
        const drawn = (panel.rows || []).length > 0 ||
            (panel.buckets || []).reduce((sum, b) => sum + (b.count || 0), 0) > 0;
        if (panel.partial && drawn) {
            hint.className = 'text-warning panel-hint';
            hint.textContent = notes.length
                ? `Incomplete: ${notes.join('; ')}`
                : 'Incomplete: a store did not answer, so these are a lower bound.';
        } else {
            hint.className = 'text-muted panel-hint';
            hint.textContent = PANEL_HINTS[panel.type] || '';
        }
        hint.style.fontSize = '.7rem';
        return slot;
    }

    /** Replace a panel's chart area with a message. */
    panelMessage(panelId, message) {
        const slot = document.querySelector(`[data-panel-id="${panelId}"]`);
        if (!slot) return;
        // No overlay removal here. It belongs to `stopSpinning`, called once
        // when the render finishes — doing it in both places means neither
        // can be tested, and the untested one is the one that rots.
        slot.querySelector('.chart-container').classList.add('d-none');
        const empty = slot.querySelector('.panel-empty');
        empty.classList.remove('d-none');
        empty.querySelector('small').textContent = message;
    }

    renderPanel(panel) {
        const slot = this.panelSlot(panel);
        if (!slot) return;

        // A panel whose own source failed says so, rather than showing an
        // empty chart that reads as "nothing happened".
        if (panel.error) {
            this.panelMessage(panel.id, panel.error);
            return;
        }

        if (panel.type === 'trace_services') {
            this.drawServiceTable(panel, slot);
            this.removePanelOverlay(slot);
            return;
        }

        if (panel.type === 'trace_list') {
            this.drawTraceList(panel, slot);
            this.removePanelOverlay(slot);
            return;
        }

        if (panel.type === 'records') {
            this.drawRecordTable(panel, slot);
            this.removePanelOverlay(slot);
            return;
        }

        if (panel.type === 'monitors') {
            this.drawMonitorGrid(panel, slot);
            this.removePanelOverlay(slot);
            return;
        }

        if (panel.type === 'monitor_certificates') {
            this.drawCertificateTable(panel, slot);
            this.removePanelOverlay(slot);
            return;
        }

        // Two questions, one drawing: "how many records have this value" and
        // "how many of this window's alerts reached nobody" are both one
        // number under one sentence, and the sentence comes from the server
        // with the number it explains.
        if (panel.type === 'count' || panel.type === 'alerts_undelivered') {
            this.drawNumber(panel, slot);
            this.removePanelOverlay(slot);
            return;
        }

        if (panel.type === 'alerts') {
            this.drawAlertTable(panel, slot);
            this.removePanelOverlay(slot);
            return;
        }

        const buckets = panel.buckets || [];
        const total = buckets.reduce((sum, b) => sum + (b.count || 0), 0);

        // An axis full of zeroes is not "no data" — the window is drawn, the
        // answer is that nothing happened. Only say so when there is genuinely
        // nothing to plot.
        if (!buckets.length || total === 0) {
            // And only when nothing on this panel says otherwise. 'No data in
            // this window' is a claim about the DATA; a panel whose question
            // could not be asked at all — a Loki terms over a field that is
            // not a label, an Elasticsearch group-by on a field that index
            // maps as text — has no such answer, and printing one here while
            // the reason sat in the page-level alert is this project's own
            // forbidden failure. The reason arrives per panel now, so prefer
            // it to the literal.
            const reasons = (panel.warnings || []).filter(Boolean);
            this.panelMessage(panel.id,
                              reasons.length ? reasons.join('; ')
                                             : 'No data in this window');
            if (this.charts[panel.id]) {
                this.charts[panel.id].destroy();
                delete this.charts[panel.id];
            }
            return;
        }

        slot.querySelector('.chart-container').classList.remove('d-none');
        slot.querySelector('.panel-empty').classList.add('d-none');

        let canvas = slot.querySelector('canvas');
        if (!canvas) {
            // The slot previously held a service table, which replaced the
            // canvas wholesale.
            const container = slot.querySelector('.chart-container');
            container.style.overflowY = '';
            container.innerHTML = '<canvas></canvas>';
            canvas = container.querySelector('canvas');
        }
        if (panel.type === 'timeseries') {
            this.drawTimeseries(panel, canvas);
        } else {
            this.drawTerms(panel, canvas);
        }
        this.removePanelOverlay(slot);
    }

    /**
     * Clear every panel when loading fails.
     */
    showLoadError(message, payload = {}) {
        // Everything the last load drew, not the four counts alone. The
        // threshold badge, the error rate, both deltas, the baseline note,
        // the source breakdown and the window are all written by
        // `updateStats` and `renderWindow`, and none of them was touched —
        // so a board whose reload failed kept a green "Within thresholds",
        // an error rate of 10.49%, "277% vs 120", "Counted from lab-es
        // 4,311" and the window those numbers came from, under a red box
        // saying the panels could not be loaded. Measured through the
        // shipped bundle on the 502 the route answers when the search
        // fails, which is the ordinary path for a log-backend outage.
        //
        // `clearBoard` has done it this way since it was written. Calling
        // the same two methods rather than listing ids is the point: the
        // list was four ids long and the page has eleven.
        this.updateStats({});
        this.renderWindow(null);

        // Mark the filter box when the filter is what was rejected: otherwise
        // a typo there reads as "the dashboard is broken".
        const filter = document.getElementById('dashboardFilter');
        if (filter) filter.classList.toggle('is-invalid', /Invalid filter/i.test(message));

        document.querySelectorAll('.panel-slot')
            .forEach(slot => this.removePanelOverlay(slot));
        const grid = document.getElementById('panelGrid');
        if (grid && !grid.querySelector('.panel-slot')) {
            grid.innerHTML =
                '<div class="col-12 text-center py-5 text-muted">' +
                '<i class="fas fa-triangle-exclamation"></i>' +
                '<div class="mt-2"><small>Panels could not be loaded.</small></div></div>';
        }

        this.showMessage(message, (payload || {}).warnings, 'danger');
    }

    /**
     * Say something above the panels, where the reader is already looking.
     *
     * Every one of these used to go to `window.toastManager`, which nothing
     * in static/ or templates/ has ever defined — the only one that existed
     * was a stub inside the dashboard's own jsdom suite, so the suite could
     * not see the gap either. A dashboard over a query the backend refused
     * showed "Failed to load" and "Panels could not be loaded.", and the
     * reason — the one sentence that says what to do next — reached nobody.
     *
     * Built with textContent rather than innerHTML: every line here is the
     * server's, and a warning can quote the query back.
     */
    showMessage(message, warnings = [], tone = 'danger') {
        const box = document.getElementById('dashboardMessage');
        if (!box) return;

        const lines = (warnings || []).filter(Boolean);
        if (!message && !lines.length) {
            this.clearMessage();
            return;
        }

        box.className = `alert alert-${tone}`;
        box.textContent = '';
        if (message) {
            const sentence = document.createElement('div');
            sentence.textContent = message;
            box.appendChild(sentence);
        }
        if (lines.length) {
            const list = document.createElement('ul');
            list.className = 'mb-0 mt-1';
            lines.forEach(line => {
                const item = document.createElement('li');
                item.textContent = line;
                list.appendChild(item);
            });
            box.appendChild(list);
        }
    }

    /** A message left standing over a good load describes a page that is no
     *  longer on screen. */
    clearMessage() {
        const box = document.getElementById('dashboardMessage');
        if (!box) return;
        box.className = 'alert d-none';
        box.textContent = '';
    }

    getQueryParams() {
        const params = new URLSearchParams();
        const bounds = this.absoluteBounds();
        if (bounds) {
            params.set('start', bounds.start);
            params.set('end', bounds.end);
        } else {
            params.set('time_range',
                       document.getElementById('timeRange')?.value || '1h');
        }
        const filter = (document.getElementById('dashboardFilter')?.value || '').trim();
        if (filter) params.set('q', filter);
        return params.toString();
    }

    /** Copy the current view's URL, which syncUrl has already made accurate. */
    async copyLink(button) {
        this.syncUrl();
        const restore = button.innerHTML;
        try {
            await navigator.clipboard.writeText(window.location.href);
            button.innerHTML = '<i class="fas fa-check"></i>';
        } catch (e) {
            button.innerHTML = '<i class="fas fa-times"></i>';
        }
        setTimeout(() => { button.innerHTML = restore; }, 1500);
    }

    updateStats(data) {
        const set = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.textContent = value;
        };

        // A count the server did not send is one that did not run — the log
        // source was unreachable, and the response carries the panels that
        // could still be answered plus the reason. Printing 0 there is the
        // same failure-as-emptiness the panels were just stopped from
        // telling, and 0 is the loudest possible version of it: "no errors".
        // A count of zero still arrives AS zero and still reads as zero.
        const known = (value, format) =>
            (value === undefined || value === null) ? '—' : format(value);

        set('totalHits', known(data.total_hits, v => v.toLocaleString()));
        set('errorCount', known(data.error_count, v => v.toLocaleString()));
        set('warnCount', known(data.warn_count, v => v.toLocaleString()));
        set('infoCount', known(data.info_count, v => v.toLocaleString()));
        set('errorRate', known(data.error_rate, v => `${(v * 100).toFixed(2)}%`));

        this.renderDeltas(data.previous_period);
        this.renderStatus(data.status);
        this.renderSources(data.sources);
    }

    /**
     * Which log sources the four numbers were added up from, and how much
     * each gave — the Logs page's own breakdown, under the stat cards.
     *
     * A board over all sources is a sum, and a sum with no breakdown is a
     * number nobody can check: two stored rows over one cluster count every
     * record twice, and the only way to see that is two names under one
     * total. Nothing is printed for a board one source answered whole — the
     * header already names it, and a line that always says the same thing
     * is a line nobody reads — but a source that did not answer is named
     * even when it is the only one, because its zero is not a zero.
     *
     * textContent throughout: the names are whatever somebody typed on the
     * configuration page.
     */
    renderSources(sources) {
        const note = document.getElementById('sourcesNote');
        if (!note) return;
        note.textContent = '';
        const rows = Array.isArray(sources) ? sources : [];
        if (!rows.length || (rows.length === 1 && !rows[0].failed)) return;

        const lead = document.createElement('span');
        lead.textContent = 'Counted from ';
        note.appendChild(lead);
        rows.forEach((row, index) => {
            const part = document.createElement('span');
            part.dataset.sourceRow = row.name;
            if (row.failed) {
                part.className = 'text-warning';
                part.textContent = `${row.name} did not answer`;
            } else {
                part.textContent =
                    `${row.name} ${Number(row.total || 0).toLocaleString()}`;
            }
            if (index) note.appendChild(document.createTextNode(' · '));
            note.appendChild(part);
        });
    }

    /**
     * Under a trace or monitor panel: which sources its rows came from.
     *
     * Printed when more than one was asked, or when one that was asked did
     * not answer — the same rule as `renderSources`, for the same reason. A
     * board pinned to a Loki reads its traces from every trace store, and
     * this is where that is seen; a panel over one source that answered is
     * left alone, because the board's header already says which.
     */
    sourcesFooter(container, panel) {
        const asked = Array.isArray(panel.sources) ? panel.sources : [];
        const missing = Array.isArray(panel.missing_sources)
            ? panel.missing_sources : [];
        if (asked.length + missing.length < 2 && !missing.length) return;

        const footer = document.createElement('div');
        footer.className = 'text-muted mt-1';
        footer.style.fontSize = '.7rem';
        footer.dataset.sources = asked.join(',');
        footer.textContent = asked.length
            ? `From ${asked.join(', ')}`
            : 'From no source that answered';
        if (missing.length) {
            const silent = document.createElement('span');
            silent.className = 'text-warning';
            silent.textContent = `; ${missing.join(', ')} did not answer`;
            footer.appendChild(silent);
        }
        container.appendChild(footer);
    }

    /**
     * Show whether the dashboard is outside what its owner calls normal.
     *
     * Hidden entirely when no threshold is set: a green "OK" badge on a
     * dashboard nobody defined normal for is a claim we cannot support, and
     * once people see it they stop reading the numbers.
     */
    renderStatus(status) {
        const badge = document.getElementById('statusBadge');
        const card = document.getElementById('cardError');
        card?.classList.remove('border-danger', 'border-warning');

        if (!badge) return;
        if (!status) {
            badge.classList.add('d-none');
            return;
        }

        const styles = {
            ok: ['bg-success-subtle text-success', 'fa-check', 'Within thresholds'],
            warning: ['bg-warning-subtle text-warning', 'fa-triangle-exclamation', 'Warning'],
            critical: ['bg-danger-subtle text-danger', 'fa-circle-exclamation', 'Critical'],
        };
        const [classes, icon, label] = styles[status.level] || styles.ok;

        badge.className = `badge align-middle ${classes}`;
        badge.innerHTML = `<i class="fas ${icon}"></i> ${label}`;
        badge.title = status.breaches.length
            ? status.breaches.map(b => b.text).join('\n')
            : 'Every configured threshold is satisfied.';

        // Mark the card the breach is about, so the badge points somewhere.
        // The mapping lives here because which card shows which metric is a
        // layout question; the server has no business knowing element ids.
        const cards = { error_rate: 'cardError', error_count: 'cardError' };
        status.breaches.forEach(breach => {
            document.getElementById(cards[breach.metric])
                ?.classList.add(breach.level === 'critical' ? 'border-danger'
                                                            : 'border-warning');
        });
    }

    /**
     * How each count moved against the window immediately before this one.
     *
     * Direction is not the same as goodness: more errors is bad, more logs is
     * merely different. Errors and warnings get red/green; totals and info are
     * left neutral so the colour never implies a judgement we cannot make.
     */
    renderDeltas(previous) {
        const fields = [
            ['totalHits', 'total_hits', 'neutral'],
            ['errorCount', 'error_count', 'bad-when-up'],
            ['warnCount', 'warn_count', 'bad-when-up'],
            ['infoCount', 'info_count', 'neutral'],
        ];

        const note = document.getElementById('baselineNote');
        if (!previous) {
            fields.forEach(([id]) => {
                const el = document.getElementById(`${id}Delta`);
                if (el) el.innerHTML = '&nbsp;';
            });
            if (note) note.textContent = '';
            return;
        }

        fields.forEach(([id, key, mood]) => {
            const el = document.getElementById(`${id}Delta`);
            if (!el) return;

            const change = previous.change ? previous.change[key] : null;
            const before = previous[key];

            if (change === null || change === undefined) {
                // No baseline to divide by. Say so rather than print a
                // meaningless "+100%" against a previous value of zero.
                el.className = 'stat-delta text-muted';
                el.textContent = before === 0 ? 'none in previous period' : 'no comparison';
                return;
            }

            const up = change >= 0;
            const pct = Math.abs(change * 100);
            const shown = pct >= 100 ? pct.toFixed(0) : pct.toFixed(1);
            const tone = mood === 'neutral' ? 'text-muted'
                       : (up ? 'text-danger' : 'text-success');

            el.className = `stat-delta ${tone}`;
            el.innerHTML =
                `<i class="fas fa-arrow-${up ? 'up' : 'down'}"></i> ${shown}% ` +
                `<span class="text-muted">vs ${(before || 0).toLocaleString()}</span>`;
        });

        if (note && previous.window) {
            const from = new Date(previous.window.start);
            const to = new Date(previous.window.end);
            note.innerHTML =
                `<i class="fas fa-info-circle"></i> Compared against the preceding window ` +
                `(${from.toLocaleString()} &rarr; ${to.toLocaleString()}). Click any card to see the records.`;
            // A baseline whose aggregation only partly answered gives counts
            // that are a FLOOR, and every percentage above is measured
            // against them. It used to arrive as exact numbers with its
            // reasons dropped, because the payload carries the CURRENT
            // window's warnings only — so a baseline that failed where this
            // window did not read as a clean comparison.
            //
            // textContent, not innerHTML: the reason is whatever the backend
            // said.
            if (previous.partial) {
                const said = document.createElement('span');
                said.className = 'text-warning';
                const reasons = (previous.warnings || []).filter(Boolean);
                said.textContent = ' The preceding window answered only in '
                    + 'part, so these percentages are a lower bound'
                    + (reasons.length ? `: ${reasons.join('; ')}` : '.');
                note.appendChild(said);
            }
        }
    }

    /**
     * The bounds that were actually queried, under the control that named them.
     *
     * The response has carried this block since the absolute range shipped
     * and nothing read it, which made it a field with no consumer and the
     * page a screen with no answer to "which hour is this?". Two readers need
     * it. "Last 1 hour" does not say which hour — on a board left open since
     * this morning it is the hour that ended when the last refresh ran, not
     * the one ending now. And every window is aligned outwards onto cache
     * boundaries before it is asked, so an hour somebody typed exactly is
     * queried as sixty-one minutes: harmless in an aggregation, and worth a
     * minute of confusion to anyone comparing a count against another tool.
     * Printing the bounds is the whole fix for both.
     *
     * `bounds` rather than `window`, which is taken.
     */
    renderWindow(bounds) {
        const el = document.getElementById('resolvedWindow');
        if (!el) return;
        if (!bounds || !bounds.start || !bounds.end) {
            el.textContent = '';
            return;
        }
        const from = new Date(bounds.start);
        const to = new Date(bounds.end);
        if (isNaN(from.getTime()) || isNaN(to.getTime())) {
            el.textContent = '';
            return;
        }
        el.textContent =
            `Asked over ${from.toLocaleString()} → ${to.toLocaleString()}`;
    }

    // `showStatsError` used to be here: the four counts, their deltas and
    // the error rate, blanked. Nothing called it — grep over static/,
    // templates/, tests/ and src/ found the definition and no caller — and
    // it was a third answer to a question `updateStats({})` already
    // answers completely, which is what `showLoadError` calls now. A
    // cleanup nobody runs is not a cleanup, and three of them is how the
    // one that runs ends up being the shortest.

    // ---------------------------------------------------------------
    // Click-through: every number on this page is a question, and the
    // answer is always a list of records. Charts that cannot be opened
    // leave the user re-typing the filter by hand in the Logs screen.
    // ---------------------------------------------------------------

    /**
     * Open the Logs screen filtered to a slice of this dashboard.
     *
     * The dashboard's own query is always carried across — otherwise clicking
     * "payment-service" on a dashboard scoped to one environment would show
     * that service everywhere.
     */
    openLogs({ level = null, service = null, extra = null,
               start = null, end = null } = {}) {
        const clauses = [];
        // The effective query the server actually ran, so a drill-down keeps
        // any ad-hoc filter. Falling back to the stored query would quietly
        // widen the result set past what is on screen.
        const base = (this.lastData?.effective_query || this.dashboardQuery || '*').trim();
        if (base && base !== '*') clauses.push(`(${base})`);
        if (level) clauses.push(`level:${queryValue(level)}`);
        if (service) clauses.push(`service:${quoted(service)}`);
        // Any other field a panel groups by, already quoted by fieldFilter.
        if (extra) clauses.push(extra);

        const params = new URLSearchParams();
        params.set('query', clauses.length ? clauses.join(' AND ') : '*');
        // The dashboard itself, so the Logs screen can be answered inside its
        // reach. The query alone was not enough: the dashboard queries its own
        // index patterns intersected with the viewer's scope, and /api/search
        // with no dashboard searches everything the scope allows — so a
        // drill-down from a dashboard scoped to `app-logs-*` returned records
        // from every index the role could read: 91,407 against the lab where
        // the card said 30,576.
        params.set('dashboard', this.dashboardId);

        // The window the BOARD is on, not the name of the control that chose
        // it. `time_range` used to be forwarded raw, which became "custom" the
        // moment an absolute range was in use — and the Logs page cannot use
        // that: it selects "custom" with two empty boxes, issues no search,
        // and says "Please select both start and end time". So every stat
        // card and every terms panel on a board pointed at a past incident
        // opened a dead end, for exactly the reader the absolute range was
        // built for — somebody looking at last Tuesday who then wants the
        // records behind a number. Only the histogram path, which passes
        // explicit bucket bounds, ever survived.
        const bucketed = start && end;
        const bounds = bucketed ? null : this.absoluteBounds();
        if (bucketed) {
            params.set('start', this.pickerTime(start));
            params.set('end', this.pickerTime(end));
        } else if (bounds) {
            params.set('start', this.pickerTime(new Date(bounds.start)));
            params.set('end', this.pickerTime(new Date(bounds.end)));
        } else {
            params.set('time_range', document.getElementById('timeRange')?.value || '1h');
        }

        window.open(`/logs?${params.toString()}`, '_blank');
    }

    /** Format for the Logs page date pickers (`Y-m-d H:i`, local time). */
    pickerTime(date) {
        const p = n => String(n).padStart(2, '0');
        return `${date.getFullYear()}-${p(date.getMonth() + 1)}-${p(date.getDate())} `
             + `${p(date.getHours())}:${p(date.getMinutes())}`;
    }

    /**
     * The span a single time bucket covers.
     *
     * Read off the gap between neighbouring buckets rather than re-deriving it
     * from the time range: the server chooses the interval, and guessing it
     * again here is how the two drift apart.
     */
    bucketWindow(buckets, index) {
        if (!buckets || !buckets.length) return null;
        const start = new Date(buckets[index].key_text || buckets[index].key);
        const neighbour = buckets[index + 1] || buckets[index - 1];
        if (!neighbour) return null;
        const step = Math.abs(new Date(neighbour.key_text || neighbour.key) - start);
        return { start, end: new Date(start.getTime() + step) };
    }

    /**
     * The query behind a stat card, as the SERVER groups severities.
     *
     * The card's number and the card's click were written apart: the server
     * sums ERROR and FATAL into one error count and WARN and WARNING into one
     * warn count, and this file asked for `level:ERROR` and `level:WARN`. So
     * the card opened fewer records than it displayed — against the lab, a
     * card reading 3,086 opened 2,767, the 319 FATAL records it had counted
     * being unreachable from the number that counted them.
     *
     * The grouping comes down with the counts, so the two move together.
     * `LEVEL_GROUPS` at the top of this file is the same table for a click
     * made before the first response has landed;
     * `tests/test_dashboard_contract.py` fails if the two ever differ.
     */
    levelQuery(group) {
        const fromServer = this.lastData?.level_queries?.[group];
        if (fromServer) return fromServer;
        const levels = LEVEL_GROUPS[group] || [String(group).toUpperCase()];
        return `(${levels.map(level => `level:${level}`).join(' OR ')})`;
    }

    setupStatCards() {
        const cards = [
            ['cardTotal', null],
            ['cardError', 'error'],
            ['cardWarn', 'warn'],
            ['cardInfo', 'info'],
        ];
        cards.forEach(([id, group]) => {
            const el = document.getElementById(id);
            if (!el) return;
            // `extra` rather than `level`, because a card stands for a GROUP
            // of levels and `level:` takes one value.
            const open = () => this.openLogs(
                group ? { extra: this.levelQuery(group) } : {});
            el.addEventListener('click', open);
            el.addEventListener('keydown', e => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    open();
                }
            });
        });
    }

    /**
     * Colours by severity, so ERROR is red on every panel that mentions it.
     *
     * A palette assigned by position would paint the same level differently on
     * two panels of the same page, which is worse than no colour at all.
     */
    static seriesColour(label, index) {
        const bySeverity = {
            ERROR: '--fill-red', FATAL: '--fill-red-strong',
            CRITICAL: '--fill-red-strong',
            WARN: '--fill-yellow', WARNING: '--fill-yellow',
            INFO: '--fill-blue', DEBUG: '--fill-purple', TRACE: '--text-muted',
            SUCCESS: '--fill-green', NOTICE: '--fill-accent',
        };
        const known = bySeverity[String(label).toUpperCase()];
        if (known) return paletteColour(known);
        const palette = paletteColour('--chart-series').split(',');
        return palette[index % palette.length].trim();
    }

    static axisStyle() {
        const font = { family: 'SF Mono, Monaco, monospace' };
        // The two colours a chart needs from the page rather than from its
        // data. Written out, an axis tuned for a dark page is invisible on a
        // light one — the gridlines especially, which are a shade of the
        // background by design.
        return {
            ticks: { color: paletteColour('--text-muted'), font },
            grid: { color: paletteColour('--border') },
        };
    }

    /**
     * Stacked bars over time, one series per split value.
     *
     * Series are derived from the data rather than hardcoded to the severity
     * levels: a panel split by service has as many series as there are
     * services, and a fixed four-series chart would drop the rest silently.
     */
    drawTimeseries(panel, canvas) {
        const buckets = panel.buckets;
        const labels = buckets.map(b => new Date(b.key).toLocaleTimeString(
            [], { hour: '2-digit', minute: '2-digit', hour12: false }));

        let datasets;
        if (panel.split_by) {
            const names = [];
            buckets.forEach(b => (b.sub?.split || []).forEach(v => {
                if (!names.includes(v.key)) names.push(v.key);
            }));
            datasets = names.map((name, i) => ({
                label: name,
                data: buckets.map(b =>
                    (b.sub?.split || []).find(v => v.key === name)?.count || 0),
                backgroundColor: AsyncDashboard.seriesColour(name, i),
                borderWidth: 0,
                stack: 'panel',
            }));
        } else {
            datasets = [{
                label: 'Count',
                data: buckets.map(b => b.count),
                backgroundColor: paletteColour('--fill-accent'),
                borderWidth: 0,
            }];
        }

        this.upsertChart(panel.id, canvas, {
            type: 'bar',
            data: { labels, datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom',
                                     labels: { color: paletteColour('--text-primary'),
                                               boxWidth: 12 } } },
                onHover: (e, els) => {
                    e.native.target.style.cursor = els.length ? 'pointer' : 'default';
                },
                onClick: (e, els) => {
                    if (!els.length) return;
                    const { index, datasetIndex } = els[0];
                    const window_ = this.bucketWindow(buckets, index) || {};
                    const value = panel.split_by
                        ? this.charts[panel.id].data.datasets[datasetIndex].label
                        : null;
                    this.openLogs({ ...window_, ...this.fieldFilter(panel.split_by, value) });
                },
                scales: { x: { stacked: true, ...AsyncDashboard.axisStyle() },
                          y: { stacked: true, beginAtZero: true,
                               ...AsyncDashboard.axisStyle() } },
            },
        });
    }

    /**
     * Top values of a field. A donut for a handful, bars beyond that —
     * a donut with fifteen slices is a colour-matching exercise.
     */
    drawTerms(panel, canvas) {
        const labels = panel.buckets.map(b => b.key);
        const values = panel.buckets.map(b => b.count);
        const colours = labels.map((l, i) => AsyncDashboard.seriesColour(l, i));
        const donut = labels.length <= 6;

        const click = (e, els) => {
            if (!els.length) return;
            this.openLogs(this.fieldFilter(panel.field, labels[els[0].index]));
        };
        const hover = (e, els) => {
            e.native.target.style.cursor = els.length ? 'pointer' : 'default';
        };

        this.upsertChart(panel.id, canvas, donut ? {
            type: 'doughnut',
            data: { labels, datasets: [{ data: values, backgroundColor: colours,
                                         borderColor: paletteColour('--surface-page'),
                                         borderWidth: 3 }] },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom',
                                     labels: { color: paletteColour('--text-primary'),
                                               boxWidth: 12 } } },
                onHover: hover, onClick: click,
            },
        } : {
            type: 'bar',
            data: { labels, datasets: [{ data: values, backgroundColor: colours,
                                         borderWidth: 0, borderRadius: 3 }] },
            options: {
                indexAxis: 'y',
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                onHover: hover, onClick: click,
                scales: { x: { beginAtZero: true, ...AsyncDashboard.axisStyle() },
                          y: AsyncDashboard.axisStyle() },
            },
        });
    }

    /**
     * Services with span counts and error rates.
     *
     * A table rather than a chart: three numbers per row, and the error rate
     * is what the eye is looking for. Bars would encode one of the three and
     * hide the rest.
     */
    drawServiceTable(panel, slot) {
        const rows = panel.rows || [];
        const container = slot.querySelector('.chart-container');

        if (!rows.length) {
            // An empty list from a store that did not answer is not an empty
            // window, and "No trace data in this window" is the one sentence
            // that cannot be told apart from it.
            this.panelMessage(panel.id, panel.partial
                ? ((panel.warnings || []).filter(Boolean).join('; ')
                   || 'No trace data could be read: a store did not answer.')
                : 'No trace data in this window');
            return;
        }

        slot.querySelector('.panel-empty').classList.add('d-none');
        container.classList.remove('d-none');
        container.style.overflowY = 'auto';

        const escape = escapeHtml;

        container.innerHTML =
            '<table class="table table-hover table-dense mb-0">' +
            '<thead><tr><th>Service</th><th class="text-end">Spans</th>' +
            '<th class="text-end">Errors</th><th class="text-end">Error rate</th>' +
            '</tr></thead><tbody>' +
            rows.map(row => {
                const rate = (row.error_rate * 100).toFixed(2);
                // Colour the rate, not the row: a busy service with a healthy
                // error rate should not look alarming just for being busy.
                const tone = row.error_rate >= 0.05 ? 'text-danger'
                           : row.error_rate > 0 ? 'text-warning' : 'text-muted';
                return `<tr data-service="${escape(row.name)}" role="button">
                    <td>${escape(row.name)}</td>
                    <td class="text-end">${row.span_count.toLocaleString()}</td>
                    <td class="text-end">${row.error_count.toLocaleString()}</td>
                    <td class="text-end ${tone}">${rate}%</td></tr>`;
            }).join('') + '</tbody></table>';
        this.sourcesFooter(container, panel);

        container.querySelectorAll('[data-service]').forEach(row => {
            row.addEventListener('click', () => {
                window.open(`/traces?service=${encodeURIComponent(row.dataset.service)}`,
                            '_blank');
            });
        });
    }

    /**
     * The newest records the board matches, on the board.
     *
     * The panel this replaces was a CLICK: to see a record behind a number
     * you left for the Logs page in another tab and lost the board. The
     * rows here are the same query the charts were drawn from, ad-hoc filter
     * and all, so the table and the bars above it cannot disagree.
     *
     * The footer is the honest half. A source that reports a match count
     * says "10 of 5,015"; Loki returns up to a limit and stops, so its total
     * is the number returned and saying "10 of 10" would invent a fact about
     * the window. `counted` comes from the source and decides which sentence
     * is printed — never the numbers, because len(rows) === total is also
     * what a quiet hour on Elasticsearch looks like.
     *
     * A reason reaches the screen whether or not the table has rows in it.
     * It used to reach the screen only when the table was EMPTY, so a page
     * the source answered short, and a footer that disagrees with the stat
     * card above it, both drew a complete-looking table with the sentence
     * that explains them dropped on the floor.
     */
    drawRecordTable(panel, slot) {
        const rows = panel.rows || [];
        const notes = (panel.warnings || []).filter(Boolean);

        if (!rows.length) {
            // A store that did not answer is not an empty window, and this
            // panel is read as evidence for the numbers above it.
            this.panelMessage(panel.id, notes.length
                ? notes.join('; ')
                : 'No records in this window');
            return;
        }

        const container = this.panelBody(slot);
        const escape = escapeHtml;
        const shown = rows.length.toLocaleString();
        const caption = panel.counted
            ? `Showing ${shown} of ${(panel.total || 0).toLocaleString()} matching records`
            : `Showing ${shown} — this source does not report a match count`;

        container.innerHTML =
            `<div class="text-muted mb-1" style="font-size:.7rem">${
                escape(caption)}</div>` +
            (notes.length
                ? `<div class="text-warning mb-1" style="font-size:.7rem">${
                    escape(notes.join(' '))}</div>`
                : '') +
            '<table class="table table-hover table-dense mb-0">' +
            '<thead><tr><th>Time</th><th>Severity</th><th>Service</th>' +
            '<th>Message</th></tr></thead><tbody>' +
            rows.map(row => {
                const level = String(row.severity || '').toUpperCase();
                const tone = (level === 'ERROR' || level === 'FATAL') ? 'text-danger'
                           : (level === 'WARN' || level === 'WARNING') ? 'text-warning'
                           : 'text-muted';
                const when = row.timestamp
                    ? new Date(row.timestamp).toLocaleString()
                    : '';
                // The severity the BOARD counted by, not the source's own
                // casing. Every bar and every stat card on this board is
                // labelled with the normalised form, and this table is read
                // as the records behind those numbers: measured against the
                // lab at 24h, Loki and VictoriaLogs return severity_text
                // 'error'/'info' for records the charts beside them label
                // ERROR and INFO, so the table read in a different language
                // from the panel above it. The raw word the source wrote is
                // kept in the title, where it answers "what does the
                // document actually say" without contradicting the chart.
                const raw = row.severity_text || '';
                return `<tr>
                    <td class="text-nowrap">${escape(when)}</td>
                    <td class="${tone}" title="${escape(raw)}">${
                        escape(level)}</td>
                    <td>${escape(row.service || '')}</td>
                    <td class="text-truncate" style="max-width:22rem" title="${
                        escape(row.body || '')}">${escape(row.body || '')}</td>
                    </tr>`;
            }).join('') + '</tbody></table>';
    }

    /**
     * Individual traces for one service: the slowest, the newest, or the
     * ones that failed.
     *
     * A row's click opens the waterfall carrying the window being looked at
     * and the store that answered. Both matter: a trace detail page opened
     * at the default range reports a trace from last Tuesday as missing, and
     * one opened with no source looks in whichever store is first and
     * reports a Jaeger trace as missing for the same reason.
     */
    drawTraceList(panel, slot) {
        const rows = panel.rows || [];
        const notes = (panel.warnings || []).filter(Boolean);

        if (!rows.length) {
            this.panelMessage(panel.id, panel.partial
                ? (notes.join('; ')
                   || 'No traces could be read: a store did not answer.')
                : `No trace through ${panel.service} in this window`);
            return;
        }

        const container = this.panelBody(slot);
        const escape = escapeHtml;
        // The window these rows came from, not the picker's current value:
        // the two differ while a change is still loading, and the link has
        // to open the window the row was found in.
        const range = this.lastData?.time_range
            || document.getElementById('timeRange')?.value || '1h';

        container.innerHTML =
            '<table class="table table-hover table-dense mb-0">' +
            '<thead><tr><th>Trace</th><th>Service</th><th>Operation</th>' +
            '<th class="text-end">Duration</th></tr></thead><tbody>' +
            rows.map(row => {
                const tone = row.has_error ? 'text-danger' : '';
                // The service is a COLUMN because a row need not belong to
                // the service the card is titled for: Tempo and Jaeger
                // describe a trace by its root span, so a panel asking for
                // cache-tier lists rows labelled mobile-bff (measured on the
                // lab: 6 of 8 Tempo services and 5 of 7 Jaeger ones answer
                // with another service's name). That is adapter behaviour
                // the Traces page shares and documents — but with the name
                // only in a title= tooltip, a card headed for one service
                // silently listed another's work.
                return `<tr data-trace="${escape(row.trace_id)}" data-source="${
                        escape(row.source || '')}" role="button" class="${tone}">
                    <td><code>${escape(String(row.trace_id).slice(0, 12))}</code>${
                        row.has_error
                            ? ' <span title="This trace has an error">!</span>'
                            : ''}</td>
                    <td class="text-truncate" style="max-width:9rem">${
                        escape(row.service || '')}</td>
                    <td class="text-truncate" style="max-width:14rem" title="${
                        escape(`${row.service || ''} ${row.name || ''}`)}">${
                        escape(row.name || '')}</td>
                    <td class="text-end text-nowrap">${
                        AsyncDashboard.duration(row.duration_us)}</td></tr>`;
            }).join('') + '</tbody></table>';
        this.sourcesFooter(container, panel);

        container.querySelectorAll('[data-trace]').forEach(row => {
            row.addEventListener('click', () => {
                const params = new URLSearchParams({ time_range: range });
                if (row.dataset.source) params.set('source', row.dataset.source);
                window.open(`/traces/${encodeURIComponent(row.dataset.trace)}?${
                    params.toString()}`, '_blank');
            });
        });
    }

    /** Microseconds, in the unit a reader can compare two rows in. */
    static duration(microseconds) {
        const us = Number(microseconds);
        if (!Number.isFinite(us)) return '';
        if (us >= 1000000) return `${(us / 1000000).toFixed(2)} s`;
        if (us >= 1000) return `${(us / 1000).toFixed(1)} ms`;
        return `${Math.round(us)} µs`;
    }

    /**
     * The panel body, emptied and ready for markup rather than a canvas.
     *
     * Shared by the two monitor renderers: both replace the chart area
     * wholesale, and both have to put the `.panel-empty` block away first or
     * a panel that was empty a refresh ago keeps its message under the new
     * content.
     */
    panelBody(slot) {
        slot.querySelector('.panel-empty').classList.add('d-none');
        const container = slot.querySelector('.chart-container');
        container.classList.remove('d-none');
        container.style.overflowY = 'auto';
        return container;
    }

    /**
     * One number, and the sentence saying what it counted.
     *
     * Zero is a real answer here and is drawn as `0`, never as "No data in
     * this window": the panel asked how many records have one value, and
     * none is the answer. What is NOT drawn as a number is a question that
     * could not be asked — a field this source cannot aggregate, a value
     * below the terms cut, a permission the role does not have — which
     * arrives as `error` and is printed where the number would be. That is
     * why the server sends `number` absent rather than 0 in those cases:
     * `panel.number || 0` here would have turned every one of them into a
     * confident zero. And it is `number` and not `value` because `value` is
     * the count panel's own definition — the string the author asked to be
     * counted — so one key would have drawn `Number("ERROR")`: NaN.
     *
     * The caption is the server's sentence, not the author's title. A big
     * number under "Checkout" is a number only its author can check.
     */
    drawNumber(panel, slot) {
        if (panel.number === null || panel.number === undefined) {
            // Nothing filled this panel. Reachable only by forgetting a
            // filler, which is the failure the signal table exists to catch
            // — and an unfilled number panel must not fall through to a
            // blank card that reads as calm.
            this.panelMessage(panel.id, 'This number could not be counted.');
            return;
        }

        const container = this.panelBody(slot);
        // No scrollbar around two lines of text.
        container.style.overflowY = 'hidden';
        container.innerHTML =
            '<div class="d-flex flex-column justify-content-center '
            + 'align-items-center text-center h-100">'
            + `<div class="fw-bold" style="font-size:2.5rem;line-height:1.1"
                     data-number>${Number(panel.number).toLocaleString()}</div>`
            + `<div class="text-muted mt-1" style="font-size:.75rem">${
                escapeHtml(panel.question || '')}</div>`
            + '</div>';
    }

    /**
     * What WDash's own alerting said in this window.
     *
     * An empty table is drawn as "no alert fired in this window" and not as
     * anything vaguer, because the OTHER reading of an empty answer — no
     * rule is configured, so nothing can fire — is refused by the server
     * with that sentence instead. By the time rows reach here, alerting
     * exists and this window was quiet.
     *
     * Whether a row was delivered is the column the panel exists for: an
     * alert nobody received reads as nothing being wrong, and the failure
     * that sent it nowhere is written on the row that failed.
     */
    drawAlertTable(panel, slot) {
        const rows = panel.rows || [];

        if (!rows.length) {
            this.panelMessage(panel.id, 'No alert fired in this window.');
            return;
        }

        const container = this.panelBody(slot);
        const escape = escapeHtml;
        const total = Number(panel.total || rows.length);
        const caption = `Showing ${rows.length.toLocaleString()} of ${
            total.toLocaleString()} in this window`;

        container.innerHTML =
            `<div class="text-muted mb-1" style="font-size:.7rem">${
                escape(caption)}</div>` +
            '<table class="table table-hover table-dense mb-0">' +
            '<thead><tr><th>Time</th><th>Rule</th><th>About</th>' +
            '<th>What</th><th>Delivered</th></tr></thead><tbody>' +
            rows.map(row => {
                const when = row.at ? new Date(row.at).toLocaleString() : '';
                const firing = row.transition === 'firing';
                const said = row.delivered
                    ? '<span class="text-muted">yes</span>'
                    : `<span class="text-danger" data-undelivered title="${
                        escape(row.delivery_error || '')}">no${
                        row.delivery_error
                            ? ` — ${escape(row.delivery_error)}` : ''
                      }</span>`;
                return `<tr>
                    <td class="text-nowrap">${escape(when)}</td>
                    <td>${escape(row.rule || '')}</td>
                    <td class="text-truncate" style="max-width:12rem"
                        title="${escape(row.subject || '')}">${
                        escape(row.subject || '')}</td>
                    <td class="${firing ? 'text-danger' : 'text-success'}">${
                        escape(row.transition || '')}</td>
                    <td class="text-truncate" style="max-width:14rem">${
                        said}</td>
                    </tr>`;
            }).join('') + '</tbody></table>';
    }

    /**
     * One cell per check, down first.
     *
     * This is the panel that separates a quiet night from a dead log
     * shipper, so an empty answer is never drawn as calm: a listing that
     * came back short says which source did not answer, and a window with
     * no check in it says that rather than showing nothing.
     *
     * Two questions out of one fetch — "is it up now" and "was it up all
     * window" — and the panel says WHICH in words above the cells. A grid
     * of green cells reading 100% and a grid of green cells reading "up"
     * look alike and are different claims.
     */
    drawMonitorGrid(panel, slot) {
        const rows = panel.rows || [];
        const availability = panel.view === 'availability';

        if (!rows.length) {
            this.panelMessage(panel.id, panel.partial
                ? ((panel.warnings || []).filter(Boolean).join('; ')
                   || 'No monitor could be read: a source did not answer.')
                : 'No monitor has reported in this window.');
            return;
        }

        const container = this.panelBody(slot);
        const counts = panel.counts || {};
        const caption = availability
            ? `Availability over the window, from the checks that ran — ${
                rows.length} check${rows.length === 1 ? '' : 's'}`
            : `Status at the last check — ${counts.down || 0} down, ${
                counts.unknown || 0} unknown, ${counts.up || 0} up`;

        const cell = (row) => {
            const measure = availability
                // Never "100%" over a check that did not run: 0 of 0 is not
                // availability, and the count is beside the figure because
                // 100% of 12 checks and 100% of 2,832 are not one claim.
                ? (row.availability === null || row.availability === undefined
                    ? '<small class="text-muted">no check ran</small>'
                    : `<strong>${row.availability}%</strong>` +
                      `<small class="text-muted"> of ${
                          (row.checks || 0).toLocaleString()}</small>`)
                : (row.duration_ms === null || row.duration_ms === undefined
                    ? ''
                    : `<small class="text-muted">${row.duration_ms} ms</small>`);
            const when = row.checked_at
                ? new Date(row.checked_at).toLocaleString()
                : 'never checked';
            return `<div class="border rounded px-2 py-1" role="button"
                         data-monitor="${escapeHtml(row.id)}"
                         style="min-width:11rem;flex:1 1 11rem">
                <div class="d-flex justify-content-between align-items-center gap-2">
                  <span class="monitor-status ${escapeHtml(row.status)}">${
                      escapeHtml(row.status)}</span>
                  ${measure}
                </div>
                <div class="text-truncate mt-1" title="${escapeHtml(row.name)}"
                     style="font-size:.8rem">${escapeHtml(row.name)}</div>
                <div class="text-muted text-truncate" style="font-size:.7rem"
                     title="${escapeHtml(when)}">${escapeHtml(when)}</div>
                ${row.error
                    ? `<div class="text-danger text-truncate" style="font-size:.7rem"
                            title="${escapeHtml(row.error)}">${
                           escapeHtml(row.error)}</div>`
                    : ''}
            </div>`;
        };

        container.innerHTML =
            `<div class="text-muted mb-2" style="font-size:.75rem">${
                escapeHtml(caption)}</div>` +
            '<div class="d-flex flex-wrap gap-2">' + rows.map(cell).join('') +
            '</div>';
        this.sourcesFooter(container, panel);

        container.querySelectorAll('[data-monitor]').forEach(element => {
            element.addEventListener('click', () => {
                window.open(monitorUrl(element.dataset.monitor), '_blank');
            });
        });
    }

    /**
     * What the checks saw on the wire, soonest expiry first.
     *
     * The bands and their words are the server's — `_certificate_state`,
     * which the Monitors page uses too — so the product cannot grow a second
     * definition of "expiring soon" in a template nobody remembers.
     */
    drawCertificateTable(panel, slot) {
        const rows = panel.rows || [];
        // "None of these checks use TLS" is a claim about the endpoints, and
        // a list that is missing whichever region did not answer has no
        // right to make it — the certificate expiring tomorrow may be the one
        // that is absent.
        const short = (panel.warnings || []).filter(Boolean);
        if (!rows.length) {
            this.panelMessage(panel.id, panel.partial
                ? (short.join('; ')
                   || 'No certificate could be read: a source did not answer.')
                : 'None of the checks in this window used TLS. An HTTPS ' +
                  'monitor reports its certificate on every run.');
            return;
        }

        const container = this.panelBody(slot);
        container.innerHTML =
            '<table class="table table-hover table-dense mb-0">' +
            '<thead><tr><th style="width:6rem">Expires in</th>' +
            '<th>Common name</th><th>Seen by</th></tr></thead><tbody>' +
            rows.map(row => {
                // `expired` is not "very soon": it has already happened, and
                // it is not another number in the same series.
                const chip = row.expired
                    ? '<span class="expiry-chip expired">expired</span>'
                    : (row.days_remaining === null || row.days_remaining === undefined
                        ? '<span class="text-muted">unknown</span>'
                        : `<span class="expiry-chip ${escapeHtml(row.state)}">${
                            row.days_remaining}d</span>`);
                // A row is a certificate; the checks that saw it are the
                // third column. It was a row per check, so an endpoint
                // watched by WDash's own agent and by Heartbeat was the
                // same certificate twice on a card that answers "what
                // renews next".
                //
                // The chips stay per CHECK: whether a handshake verified,
                // and whether this check verifies at all, are answers about
                // the connection rather than about the certificate.
                // `verified` is true, false or null, and null means the
                // source did not say — Heartbeat never does. Only an
                // explicit false earns the chip; rendering null as "not
                // verified" would put a finding on every row on day one.
                const checks = (row.checks || []);
                const seen = checks.map(check => {
                    const chips =
                        (check.tls_mode === 'expiry_only'
                            ? ' <span class="badge target-chip" title="This check does not verify the certificate. The expiry is all it can vouch for.">expiry only</span>'
                            : check.verified === false
                            ? ' <span class="badge target-chip" title="This check verifies the certificate and its last run did not complete a verified handshake with this endpoint.">not verified</span>'
                            : '');
                    // The check's NAME first. It was the endpoint, because
                    // a row used to be a check; on a row that is a
                    // certificate the endpoint usually repeats the common
                    // name above it — and where it does not, which is a
                    // certificate covering several hosts, it is the detail
                    // rather than the subject.
                    return `<div class="cert-check" role="button"
                                 data-monitor="${escapeHtml(check.id)}">
                        ${escapeHtml(check.name)}${chips}
                        <div><small class="text-muted"><code>${
                            escapeHtml(check.location || '—')}</code></small></div>
                        </div>`;
                }).join('');
                return `<tr class="monitor-row-${escapeHtml(row.state)}">
                    <td>${chip}</td>
                    <td><code>${escapeHtml(row.common_name || '—')}</code>${
                        checks.length > 1
                            ? ` <span class="badge target-chip" title="One certificate, watched by ${
                                checks.length} checks.">${checks.length} checks</span>`
                            : ''}</td>
                    <td>${seen}</td></tr>`;
            }).join('') + '</tbody></table>' +
            `<div class="text-muted mt-2" style="font-size:.7rem">Warning below ${
                panel.warning_days} days, urgent below ${
                panel.critical_days}. Sorted by what expires first.</div>` +
            (panel.partial
                ? `<div class="text-warning mt-1" style="font-size:.7rem">${
                    escapeHtml('A source did not answer, so an endpoint may '
                               + 'be missing from this list: '
                               + short.join('; '))}</div>`
                : '');
        this.sourcesFooter(container, panel);

        container.querySelectorAll('[data-monitor]').forEach(element => {
            element.addEventListener('click', () => {
                window.open(monitorUrl(element.dataset.monitor), '_blank');
            });
        });
    }

    /**
     * Turn a field/value pair into something openLogs understands.
     *
     * `severity` is the one field whose neutral name differs from the query
     * language's, so it is translated here rather than at every call site.
     */
    fieldFilter(field, value) {
        if (!field || value === null || value === undefined) return {};
        if (field === 'severity') return { level: value };
        if (field === 'service') return { service: value };
        return { extra: `${field}:${quoted(value)}` };
    }

    /**
     * Create the chart, or restyle the existing one in place.
     *
     * Chart.js keeps a registry keyed by canvas, so building a second chart on
     * a canvas that already has one throws. Updating in place also keeps the
     * animation and tooltip state across a background refresh.
     */
    upsertChart(panelId, canvas, config) {
        const existing = this.charts[panelId];
        if (existing && existing.config.type === config.type) {
            existing.data = config.data;
            existing.options = config.options;
            existing.update('none');
            return;
        }
        if (existing) existing.destroy();
        this.charts[panelId] = new Chart(canvas.getContext('2d'), config);
    }

    initializeCharts() {
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not loaded');
            return;
        }

        Chart.defaults.color = paletteColour('--text-primary');
        Chart.defaults.borderColor = paletteColour('--border');
    }

    toggleAutoRefresh() {
        if (this.isAutoRefreshing) this.stopAutoRefresh();
        else this.startAutoRefresh();
    }

    startAutoRefresh() {
        const btn = document.getElementById('autoRefreshBtn');
        const seconds = this.refreshSeconds();
        // "Off" is a choice, not a rate. Starting anyway at some default
        // would ask on behalf of somebody who had just said not to. A window
        // with both ends fixed is the same refusal for a different reason:
        // last Tuesday 14:00 to 15:00 cannot answer differently in ten
        // seconds, so every one of those refreshes is ten Loki requests
        // (measured) spent re-fetching a number that cannot have moved.
        if (!btn || !seconds || this.isAbsolute()) return;

        clearInterval(this.autoRefreshInterval);
        // Quiet, and only while the tab is actually being looked at. A
        // dashboard left open in a background tab was querying every thirty
        // seconds for nobody — multiply that by the number of people who
        // never close tabs.
        this.autoRefreshInterval = setInterval(() => {
            if (document.visibilityState === 'visible') this.load({ quiet: true });
        }, seconds * 1000);
        btn.innerHTML = '<i class="fas fa-pause"></i> Stop Auto Refresh';
        btn.classList.remove('btn-outline-secondary');
        btn.classList.add('btn-success');
        this.isAutoRefreshing = true;
    }

    stopAutoRefresh() {
        clearInterval(this.autoRefreshInterval);
        this.autoRefreshInterval = null;
        this.isAutoRefreshing = false;
        const btn = document.getElementById('autoRefreshBtn');
        if (!btn) return;
        btn.innerHTML = '<i class="fas fa-play"></i> Auto Refresh';
        btn.classList.remove('btn-success');
        btn.classList.add('btn-outline-secondary');
    }

    /**
     * Make the chosen interval the one in force.
     *
     * Choosing "Off" while a board is refreshing stops it there and then —
     * the choice is about what this tab is costing the backend right now, and
     * a setting that only takes effect after a press of Stop is a setting
     * that lies for one more interval. A running timer moves to the new rate
     * for the same reason.
     */
    applyRefreshChoice() {
        const btn = document.getElementById('autoRefreshBtn');
        const seconds = this.refreshSeconds();
        // A fixed window is not a rate anybody can choose between: it cannot
        // produce a new answer at any interval. Said where the cost is said,
        // because it is the same subject — this is the one control on the
        // page whose purpose is what the board costs the backend behind it.
        const fixed = this.isAbsolute();
        const note = document.getElementById('refreshNote');
        if (note) {
            note.textContent = fixed
                ? 'Both ends of this window are fixed, so it cannot answer '
                  + 'differently: auto-refresh is unavailable while it is in force.'
                : '';
        }
        const interval = document.getElementById('refreshInterval');
        if (interval) interval.disabled = fixed;
        if (btn) btn.disabled = fixed || !seconds;
        if (fixed || !seconds) {
            if (this.isAutoRefreshing) this.stopAutoRefresh();
            return;
        }
        if (this.isAutoRefreshing) this.startAutoRefresh();
    }

    destroy() {
        if (this.autoRefreshInterval) {
            clearInterval(this.autoRefreshInterval);
        }
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
        this.charts = {};
    }
}

// CSS for loading overlay
const asyncStyles = document.createElement('style');
asyncStyles.textContent = `
    .chart-loading-overlay {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: color-mix(in srgb, var(--surface-page) 90%, transparent);
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        z-index: 10;
        border-radius: 10px;
    }
    
    .chart-loading-overlay .spinner-border {
        width: 3rem;
        height: 3rem;
    }

    /* The cards are links, so they have to look like something you can press. */
    .stat-card {
        cursor: pointer;
        transition: border-color .12s ease, transform .12s ease;
    }
    .stat-card:hover, .stat-card:focus-visible {
        border-color: var(--accent);
        transform: translateY(-2px);
        outline: none;
    }
    .stat-card .stat-jump { opacity: 0; transition: opacity .12s ease; }
    .stat-card:hover .stat-jump, .stat-card:focus-visible .stat-jump { opacity: .7; }
`;
document.head.appendChild(asyncStyles);

// Initialize async dashboard
document.addEventListener('DOMContentLoaded', function() {
    const dashboardElement = document.querySelector('[data-dashboard-id]');
    if (dashboardElement) {
        const dashboardId = dashboardElement.dataset.dashboardId;
        if (dashboardId) {
            console.log('🚀 Initializing Async Dashboard:', dashboardId);
            window.asyncDashboard = new AsyncDashboard(
                dashboardId, dashboardElement.dataset.dashboardQuery || '*');
        }
    }
});
