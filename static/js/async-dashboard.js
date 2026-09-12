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

        const timeRange = params.get('time_range');
        const select = document.getElementById('timeRange');
        if (timeRange && select
            && [...select.options].some(o => o.value === timeRange)) {
            select.value = timeRange;
        }

        const filter = params.get('q');
        const input = document.getElementById('dashboardFilter');
        if (filter && input) input.value = filter;
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
        params.set('time_range', document.getElementById('timeRange')?.value || '1h');

        const filter = (document.getElementById('dashboardFilter')?.value || '').trim();
        if (filter) params.set('q', filter);

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
            timeRange.addEventListener('change', () => { this.syncUrl(); this.load(); });
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
                             data.error ? 'warning' : 'info');

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
        slot.querySelector('.panel-title').textContent = panel.title;

        // A panel whose source answered for only some of its backends says so
        // where its numbers are. It used to draw the rows it got and nothing
        // else, so a trace store that did not reply looked like a service
        // that had gone quiet — which is the one reading this panel exists to
        // support.
        const hint = slot.querySelector('.panel-hint');
        const notes = (panel.warnings || []).filter(Boolean);
        if (panel.partial) {
            hint.className = 'text-warning panel-hint';
            hint.textContent = notes.length
                ? `Incomplete: ${notes.join('; ')}`
                : 'Incomplete: a store did not answer, so these are a lower bound.';
        } else {
            hint.className = 'text-muted panel-hint';
            hint.textContent =
                panel.type === 'timeseries' ? 'Click a segment to open those records'
                                            : 'Click a value to filter by it';
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

        const buckets = panel.buckets || [];
        const total = buckets.reduce((sum, b) => sum + (b.count || 0), 0);

        // An axis full of zeroes is not "no data" — the window is drawn, the
        // answer is that nothing happened. Only say so when there is genuinely
        // nothing to plot.
        if (!buckets.length || total === 0) {
            this.panelMessage(panel.id, 'No data in this window');
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
        ['totalHits', 'errorCount', 'warnCount', 'infoCount'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = '-';
        });

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
        const params = new URLSearchParams({
            time_range: document.getElementById('timeRange')?.value || '1h',
        });
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

        set('totalHits', (data.total_hits || 0).toLocaleString());
        set('errorCount', (data.error_count || 0).toLocaleString());
        set('warnCount', (data.warn_count || 0).toLocaleString());
        set('infoCount', (data.info_count || 0).toLocaleString());
        set('errorRate', `${((data.error_rate || 0) * 100).toFixed(2)}%`);

        this.renderDeltas(data.previous_period);
        this.renderStatus(data.status);
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
        }
    }

    showStatsError() {
        ['totalHits', 'errorCount', 'warnCount', 'infoCount'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = '-';
            const delta = document.getElementById(`${id}Delta`);
            if (delta) delta.innerHTML = '&nbsp;';
        });
        const rate = document.getElementById('errorRate');
        if (rate) rate.textContent = '-';
    }

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

        if (start && end) {
            params.set('start', this.pickerTime(start));
            params.set('end', this.pickerTime(end));
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

        const escape = (value) => String(value).replace(/[&<>"]/g,
            c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

        container.innerHTML =
            '<table class="table table-sm mb-0" style="font-size:.8rem">' +
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

        container.querySelectorAll('[data-service]').forEach(row => {
            row.addEventListener('click', () => {
                window.open(`/traces?service=${encodeURIComponent(row.dataset.service)}`,
                            '_blank');
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
        const btn = document.getElementById('autoRefreshBtn');
        if (!btn) return;

        if (this.isAutoRefreshing) {
            clearInterval(this.autoRefreshInterval);
            btn.innerHTML = '<i class="fas fa-play"></i> Auto Refresh';
            btn.classList.remove('btn-success');
            btn.classList.add('btn-outline-secondary');
            this.isAutoRefreshing = false;
        } else {
            // Quiet, and only while the tab is actually being looked at. A
            // dashboard left open in a background tab was querying every
            // thirty seconds for nobody — multiply that by the number of
            // people who never close tabs.
            this.autoRefreshInterval = setInterval(() => {
                if (document.visibilityState === 'visible') this.load({ quiet: true });
            }, 30000);
            btn.innerHTML = '<i class="fas fa-pause"></i> Stop Auto Refresh';
            btn.classList.remove('btn-outline-secondary');
            btn.classList.add('btn-success');
            this.isAutoRefreshing = true;
        }
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
