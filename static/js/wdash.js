/**
 * WDash JavaScript Utilities
 */

/**
 * Which release this file belongs to.
 *
 * The page asks for `wdash.min.js?v=<version>` — and in the shipped
 * Kubernetes deployment that file is served by an nginx SIDECAR, out of an
 * emptyDir that a COPY-STATIC-FILES INIT CONTAINER filled. That is a
 * different container from the one rendering the HTML, so the query string
 * says what the page asked for and nothing about what came back: an init
 * container left on an older tag serves last release's JavaScript under
 * this release's URL, with `expires 1y, immutable` on top of it.
 *
 * That was invisible. A deployment reported a control doing nothing, with
 * no error, no warning, and no way to tell the code that shipped from the
 * code in front of it. This is the answer: the page knows what it asked
 * for, this says what it got, and a mismatch is one line naming the cause.
 *
 * Held to `src/wdash/__init__.py` by `tests/test_version.py`, like the
 * eight other places the number lives.
 */
const WDASH_BUNDLE_VERSION = '3.1.6';

//: Readable from a console, which is where somebody asks this question.
//:
//: The minifier folds the constant into the message below, so without this
//: the shipped file states its version in prose and nowhere a person can
//: query it — and the whole point is to be askable when a page is behaving
//: like a release it is not.
if (typeof window !== 'undefined') {
    window.WDASH_BUNDLE_VERSION = WDASH_BUNDLE_VERSION;
}

/**
 * Say so when the JavaScript running is not the JavaScript this page asked
 * for. Called from the page, which is the only thing that knows the answer.
 */
function wdashCheckBundleVersion(expected) {
    if (!expected || expected === WDASH_BUNDLE_VERSION) { return true; }
    console.error(
        'WDash: this page is ' + expected + ' but the JavaScript it loaded ' +
        'is ' + WDASH_BUNDLE_VERSION + '. Something between your browser and ' +
        'the application is serving an older copy of /static. In the shipped ' +
        'Kubernetes deployment that is the nginx sidecar, whose files come ' +
        'from the copy-static-files init container: check that it is on the ' +
        'same image tag as the application container, and that no cache in ' +
        'front of it is holding /static. Until then this page is running ' +
        'code from a different release than the one it is showing you.');
    return false;
}

/**
 * A colour from the palette, by token name.
 *
 * Read at call time rather than cached at load: the palette is what a theme
 * overrides, and a value captured once would be whichever theme happened to
 * be active when the page opened.
 *
 * The same five lines are in `async-dashboard.js`. There is no module system
 * here and the load order between the two is decided by template blocks, so a
 * helper that arrives second is undefined the first time it is wanted.
 *
 * No fallback colour on purpose: a fallback is a literal, and a literal is
 * what this removes. A missing token comes back empty and the chart draws in
 * its own default — visible, and `tests/test_contrast.py` fails, because
 * every token named from a script has to exist in `:root`.
 */
function paletteColour(name) {
    return getComputedStyle(document.documentElement)
        .getPropertyValue(name).trim();
}


class WDash {
    constructor() {
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.setupTooltips();
    }

    setupEventListeners() {
        // Flash messages close themselves after 5 seconds — the success and
        // info ones, and only those the layout marks as a flash. This took
        // every success or info box on the page: the traces page's notice
        // that some services are hidden from the role was gone at 5.1s, and
        // with it the advisor's "No findings" and the setup and roles notes.
        document.querySelectorAll('.alert[data-autodismiss]').forEach(alert => {
            if (alert.classList.contains('alert-success') || alert.classList.contains('alert-info')) {
                setTimeout(() => {
                    const bsAlert = new bootstrap.Alert(alert);
                    bsAlert.close();
                }, 5000);
            }
        });

        // Smooth scroll for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
    }

    setupTooltips() {
        // Initialize Bootstrap tooltips
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }

    // Utility functions
    /**
     * Flatten a neutral record into an ordered field list for display.
     * The order matters: identifying fields first, large text (body) last.
     */
    static recordFields(record) {
        const fields = [];
        const push = (k, v) => {
            if (v !== null && v !== undefined && v !== '') fields.push([k, v]);
        };
        push('timestamp', record.timestamp);
        push('severity', record.severity_text || record.severity);
        push('service', record.service);
        push('trace_id', record.trace_id);
        push('span_id', record.span_id);
        Object.keys(record.resource || {}).sort().forEach(k => push(k, record.resource[k]));
        Object.keys(record.attributes || {}).sort().forEach(k => push(k, record.attributes[k]));
        push('body', record.body);
        return fields;
    }

    static escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * For a value inside a quoted attribute.
     *
     * `escapeHtml` is right for text and wrong here: it leaves quotes as
     * they are, so a severity of `x" style="position:fixed…` closed the
     * class attribute it was put in and wrote its own, on every row that
     * showed it. It stays as it is for text — `highlightJson` finds strings
     * by their quotes.
     */
    static escapeAttr(value) {
        return String(value == null ? '' : value).replace(/[&<>"']/g, c =>
            ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
    }

    /**
     * A number from the server, as a number.
     *
     * Totals, timings and bucket counts are Elasticsearch's own, and a
     * string where one was expected went into the page as markup: whoever
     * answered as Elasticsearch — anything on a plain-http link to it —
     * chose what every reader's browser ran. `toLocaleString` on a string
     * returns the string.
     */
    static count(value) {
        const n = Number(value);
        return Number.isFinite(n) ? n : 0;
    }

    /**
     * A value as a quoted string in the query language, whatever it holds.
     *
     * A click that filters by a value wrote it between quotes and escaped
     * nothing, so a value holding a quote closed the string and the rest was
     * query: `x" OR service:"hr-salaries` clicked in the sidebar widened the
     * search it was meant to narrow, and a Windows path ending in a
     * backslash was a syntax error.
     */
    static quoted(value) {
        return '"' + String(value == null ? '' : value)
            .replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
    }

    /**
     * The class a level badge wears. The stylesheet colours the normalised
     * levels and two raw names of its own — SUCCESS and NOTICE, which
     * normalise to UNSPECIFIED and INFO — so those keep their chip; anything
     * else is the level. Never the raw text as it came: a severity of
     * `x" style="…` closed the attribute it was put in.
     */
    static levelClass(record) {
        const raw = String((record && record.severity_text) || '').toUpperCase();
        return WDash.escapeAttr(['SUCCESS', 'NOTICE'].includes(raw) ? raw
            : ((record && record.severity) || 'INFO').toUpperCase());
    }

    /**
     * Colour a JSON document without changing a character of it.
     *
     * One pass over tokens rather than a chain of independent replaces. The
     * chain could not tell a separator from a colon INSIDE a string value, so
     * it rewrote `"09:30:12"` as `"09: 30: 12"` and `"3:2"` as `"3: 2"` —
     * corrupting timestamps and ratios on screen, and in anything copied from
     * there. Highlighting that alters the text is worse than no highlighting.
     *
     * Strings are matched first and consumed whole, so nothing inside one is
     * ever examined again.
     */
    static highlightJson(jsonStr) {
        return WDash.escapeHtml(jsonStr).replace(
            /("(?:\\.|[^"\\])*")(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g,
            (match, str, colon) => {
                if (str !== undefined) {
                    // A string followed by a colon is a key; anything else is a value.
                    return '<span class="' + (colon ? 'hl-key' : 'hl-str') + '">' +
                           str + '</span>' + (colon || '');
                }
                const cls = (match === 'true' || match === 'false') ? 'hl-bool'
                          : (match === 'null') ? 'hl-null' : 'hl-num';
                return '<span class="' + cls + '">' + match + '</span>';
            });
    }

    static isJson(str) {
        if (!str || str[0] !== '{' && str[0] !== '[') return false;
        try { JSON.parse(str); return true; } catch { return false; }
    }

    static isStackTrace(str) {
        return /^\s+at\s+/m.test(str) || /Traceback \(most recent/i.test(str) || /^\s+File "/m.test(str);
    }

    static formatMessagePreview(message) {
        const escaped = WDash.escapeHtml(message);
        const lines = escaped.split('\n');
        if (lines.length <= 1) return { html: escaped, lineCount: 1 };

        const firstLine = lines[0];
        return { html: firstLine, lineCount: lines.length };
    }

    static formatMessageFull(message) {
        if (WDash.isJson(message)) {
            try {
                const pretty = JSON.stringify(JSON.parse(message), null, 2);
                return WDash.highlightJson(pretty);
            } catch { /* fall through */ }
        }

        const escaped = WDash.escapeHtml(message);
        const lines = escaped.split('\n');

        if (WDash.isStackTrace(message)) {
            return lines.map(line => {
                if (/^\s+(at\s+|File\s+")/.test(line)) {
                    return `<span class="stack-trace-line">${line}</span>`;
                }
                return line;
            }).join('\n');
        }

        return lines.map((line, i) =>
            `<span class="line-number">${i + 1}</span>${line}`
        ).join('\n');
    }

    static formatTimestamp(timestamp) {
        try {
            const date = new Date(timestamp);
            return date.toLocaleString();
        } catch (e) {
            return timestamp;
        }
    }

    static showNotification(message, type = 'info') {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        // Text, not markup: every caller passes a sentence, and one of them
        // passes a name the user typed.
        alertDiv.append(document.createTextNode(String(message)));
        const close = document.createElement('button');
        close.type = 'button';
        close.className = 'btn-close';
        close.setAttribute('data-bs-dismiss', 'alert');
        alertDiv.append(close);
        
        document.body.appendChild(alertDiv);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.parentNode.removeChild(alertDiv);
            }
        }, 5000);
    }

    static debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    static throttle(func, limit) {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }
}

// Search functionality
class LogSearch {
    constructor() {
        this.currentPage = 0;
        this.totalResults = 0;
        this.pageSize = 50;
        this.searchForm = null;
        this.initialized = false;
        this.retryCount = 0;
        this.maxRetries = 10;
        this.clearButtonHandler = null;
        this.searchAfterStack = [];  // Stack of search_after cursors for page navigation
        this.currentSearchAfter = null;
        /**
         * Whether to label each record with the source that answered.
         *
         * Off with a single source: a badge repeated on every row that always
         * says the same thing is noise, and noise is how people stop reading
         * the row footer at all. The server decides, because only it knows how
         * many sources are configured.
         */
        this.showSources = false;
        this.init();
    }

    init() {
        // Try to get the search form
        this.searchForm = document.getElementById('searchForm');
        
        if (!this.searchForm) {
            if (this.retryCount < this.maxRetries) {
                this.retryCount++;
                console.warn(`Search form not found, retrying (${this.retryCount}/${this.maxRetries})...`);
                setTimeout(() => this.init(), 100);
                return;
            } else {
                console.error('Search form not found after maximum retries');
                return;
            }
        }

        // Prevent double initialization
        if (this.initialized) {
            console.log('LogSearch already initialized');
            return;
        }

        console.log('Setting up LogSearch event listeners...');

        // A theme switch re-resolves every token on the page and nothing on
        // a canvas: the histogram is drawn again from the bars it already has.
        document.addEventListener('wdash:theme', () => {
            if (this.histogramData) this.renderHistogram(this.histogramData);
        });

        // Set up form submit handler
        this.searchForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.currentPage = 0;
            this.currentSearchAfter = null;
            this.searchAfterStack = [];
            this.performSearch();
        });

        // Set up debounced search on input
        const queryInput = document.getElementById('query');
        if (queryInput) {
            queryInput.addEventListener('input', 
                WDash.debounce(() => {
                    this.currentPage = 0;
                    this.currentSearchAfter = null;
                    this.searchAfterStack = [];
                    this.performSearch();
                }, 500)
            );
        }

        const sourceSelect = document.getElementById('sourceSelect');
        if (sourceSelect) {
            sourceSelect.addEventListener('change', () => {
                this.currentPage = 0;
                this.currentSearchAfter = null;
                this.searchAfterStack = [];
                this.performSearch();
            });
        }

        // Set up clear button with event delegation to avoid issues
        this.setupClearButtonDelegation();
        this._setupSavedSearches();
        this._setupFieldStatsPicker();

        this.initialized = true;
        this._applyUrlParams();
        console.log('LogSearch initialized successfully');
    }

    /**
     * Prefill the form from the query string and run the search.
     *
     * This is what makes every chart elsewhere in the app a link: a dashboard
     * bar or a trace row can hand off to /logs?query=...&time_range=... and
     * land the user on exactly the records behind the number they clicked.
     * Supported: query, time_range, and start/end for an explicit window.
     */
    _applyUrlParams() {
        const params = new URLSearchParams(window.location.search);
        if (![...params.keys()].length) return;

        const set = (id, value) => {
            const el = document.getElementById(id);
            if (!el || value === null) return false;
            el.value = value;
            // The date fields are flatpickr-managed; assigning .value alone
            // leaves the picker showing the old date next to the new one.
            if (el._flatpickr) el._flatpickr.setDate(value, false);
            return true;
        };

        let touched = set('query', params.get('query'));
        touched = set('sourceSelect', params.get('source')) || touched;

        // A drill-down from a dashboard. Kept and sent back on every search
        // from this page, because the dashboard decides WHERE the query runs
        // — without it the same query is answered from the whole scope, which
        // is how clicking a stat card showed more records than the card.
        this.scopedDashboard = params.get('dashboard') || null;
        if (this.scopedDashboard) touched = true;

        // An explicit window wins over a named range: it is more specific, and
        // it is what a click on a single histogram bar produces.
        const start = params.get('start'), end = params.get('end');
        if (start && end) {
            set('timeRange', 'custom');
            document.getElementById('timeRange')?.dispatchEvent(new Event('change'));
            touched = set('startTime', start) || touched;
            touched = set('endTime', end) || touched;
        } else {
            touched = set('timeRange', params.get('time_range')) || touched;
        }

        if (touched) this.performSearch();
    }

    setupClearButtonDelegation() {
        // Use event delegation on document to ensure it always works
        // Remove any existing delegated listeners first
        if (this.clearButtonHandler) {
            document.removeEventListener('click', this.clearButtonHandler);
        }
        
        // Create the handler and store reference for cleanup
        this.clearButtonHandler = (e) => {
            if (e.target && e.target.id === 'clearBtn') {
                e.preventDefault();
                console.log('Clear button clicked via delegation');
                this.clearSearch();
            }
        };
        
        document.addEventListener('click', this.clearButtonHandler);
        console.log('Clear button delegation set up');
    }

    clearSearch() {
        console.log('Clearing search...');
        
        try {
            // Reset form
            if (this.searchForm) {
                console.log('Resetting form...');
                this.searchForm.reset();
            } else {
                console.warn('Search form not available for reset');
            }
            
            // Set default values
            const queryInput = document.getElementById('query');
            if (queryInput) {
                console.log('Setting query to *');
                queryInput.value = '*';
            } else {
                console.warn('Query input not found');
            }
            
            const sizeInput = document.getElementById('size');
            if (sizeInput) {
                console.log('Setting size to 50');
                sizeInput.value = '50';
            } else {
                console.warn('Size input not found');
            }
            
            // Clear results
            const logEntries = document.getElementById('logEntries');
            const resultsInfo = document.getElementById('resultsInfo');
            const pagination = document.getElementById('pagination');
            const emptyState = document.getElementById('emptyState');
            
            if (logEntries) {
                console.log('Clearing log entries');
                logEntries.innerHTML = '';
            }
            if (resultsInfo) {
                console.log('Clearing results info');
                resultsInfo.innerHTML = '';
            }
            if (pagination) {
                console.log('Clearing pagination');
                pagination.innerHTML = '';
            }
            if (emptyState) {
                console.log('Hiding empty state');
                emptyState.classList.add('d-none');
            }
            // And what the last search drew beside its rows: the chart, the
            // sources, its warnings and its field statistics stayed on
            // screen, describing a search that was no longer there.
            this.clearLastAnswer();

            // Hide error display
            this.hideError();
            
            // Reset pagination state
            this.currentPage = 0;
            this.totalResults = 0;
            this.pageSize = 50;
            this.currentSearchAfter = null;
            this.searchAfterStack = [];
            
            console.log('Search cleared successfully');
            
            // Show success notification
            WDash.showNotification('Search cleared', 'success');
            
        } catch (error) {
            console.error('Error clearing search:', error);
            WDash.showNotification('Error clearing search: ' + error.message, 'danger');
        }
    }

    // Method to reinitialize if needed
    reinitialize() {
        console.log('Reinitializing LogSearch...');
        
        // Clean up existing handlers
        if (this.clearButtonHandler) {
            document.removeEventListener('click', this.clearButtonHandler);
            this.clearButtonHandler = null;
        }
        
        this.initialized = false;
        this.retryCount = 0;
        this.init();
    }

    async performSearch() {
        const formData = new FormData(this.searchForm);
        const params = new URLSearchParams();
        
        params.append('q', formData.get('query') || '*');
        params.append('size', formData.get('size') || '50');

        // Only sent when there is a choice to make. Sending "the default"
        // explicitly would turn a later change of default into a silent
        // change of what saved links mean.
        const source = formData.get('source');
        if (source) params.append('source', source);

        // The dashboard this page was opened from, if any. The server
        // resolves it: the id travels, the containers do not, because a
        // client-supplied container list is not a boundary.
        if (this.scopedDashboard) params.append('dashboard', this.scopedDashboard);
        
        // Handle time range — always required
        const timeRange = document.getElementById('timeRange')?.value;
        if (timeRange && timeRange !== 'custom') {
            const now = new Date();
            let startTime;
            
            switch(timeRange) {
                case '15m':
                    startTime = new Date(now.getTime() - 15 * 60 * 1000);
                    break;
                case '1h':
                    startTime = new Date(now.getTime() - 60 * 60 * 1000);
                    break;
                case '6h':
                    startTime = new Date(now.getTime() - 6 * 60 * 60 * 1000);
                    break;
                case '24h':
                    startTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                    break;
                case '7d':
                    startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                    break;
            }
            
            if (startTime) {
                params.append('start_time', startTime.toISOString());
                params.append('end_time', now.toISOString());
            }
        } else {
            // Custom time range — validate
            const startVal = formData.get('startTime');
            const endVal = formData.get('endTime');
            if (!startVal || !endVal) {
                this.showError('Please select both start and end time for custom range.', 'validation_error');
                this.showLoading(false);
                return;
            }
            const startDate = new Date(startVal);
            const endDate = new Date(endVal);
            if (startDate >= endDate) {
                this.showError('Start time must be before end time.', 'validation_error');
                this.showLoading(false);
                return;
            }
            params.append('start_time', startDate.toISOString());
            params.append('end_time', endDate.toISOString());
        }
        
        // search_after cursor for pagination
        if (this.currentSearchAfter) {
            params.append('search_after', JSON.stringify(this.currentSearchAfter));
        }
        
        this.pageSize = parseInt(formData.get('size') || '50');
        
        this.showLoading(true);
        this.hideError();
        
        try {
            const response = await fetch('/api/search?' + params.toString());
            const data = await response.json();
            
            if (response.ok) {
                if (data.error) {
                    this.showError(data.error, data.error_type, data);
                } else {
                    this.displayResults(data);
                    this.updateIndexInfo(data);
                    this.renderSourceBreakdown(data);
                    this.loadFieldStats();
                }
            } else {
                this.showError(data.error || 'Search failed', data.error_type, data);
            }
        } catch (error) {
            console.error('Search error:', error);
            this.showError('Network error: Unable to connect to the server. Please check your connection and try again.', 'network_error');
        } finally {
            this.showLoading(false);
        }
    }
    
    updateIndexInfo(data) {
        const badgeEl = document.getElementById('totalIndicesBadge');
        if (badgeEl && data.accessible_containers) {
            badgeEl.textContent = `Available: ${data.accessible_containers.length} indices`;
        }

        // Say when this page is answering inside a dashboard's reach rather
        // than the whole of the role's. Without it the reader has no way to
        // tell a narrowed result set from all their logs.
        const scope = document.getElementById('dashboardScopeBadge');
        if (!scope) return;
        if (data.dashboard) {
            // The SOURCE as well as the index count. A dashboard may be
            // pinned to a store of its own, and /api/search answers a
            // drill-down from that store while this page's picker still
            // showed — and sent — its first option, which the server then
            // ignored. Naming it here and moving the picker to match is what
            // stops the control and the answer from disagreeing.
            const source = data.dashboard.source;
            // `*` is how the server and the picker both spell "every
            // source"; a person reads it as words.
            const label = source === '*' ? 'all sources' : source;
            scope.textContent =
                `Scoped to the "${data.dashboard.name}" dashboard`
                + ` (${label ? `${label}, ` : ''}`
                + `${(data.dashboard.containers || []).length} indices)`;
            scope.classList.remove('d-none');
            const picker = document.getElementById('sourceSelect');
            if (picker && source) picker.value = source;
        } else {
            scope.textContent = '';
            scope.classList.add('d-none');
        }
    }

    /**
     * Which source answered, and with how much.
     *
     * Two distinctions the bare numbers do not make, and both matter more
     * than the counts:
     *
     *   failed  - the source did not answer. Zero from a source that was
     *             asked and zero from a source that never replied look the
     *             same on a bar chart and mean opposite things.
     *   exact   - the source cannot report a match count (Loki returns up to
     *             a limit and stops), so its total is a floor, not a total.
     *
     * The share bar is drawn from the page counts, not the totals: it
     * describes the rows on screen, which is what someone is looking at when
     * they wonder where a record came from.
     */
    renderSourceBreakdown(data) {
        const card = document.getElementById('sourceBreakdownCard');
        const body = document.getElementById('sourceBreakdownContent');
        if (!card || !body) return;

        const sources = data.sources || [];
        // One source that answered normally tells nobody anything they did
        // not already know from the source picker.
        if (!sources.length || (sources.length === 1 && !sources[0].failed)) {
            card.classList.add('d-none');
            return;
        }
        card.classList.remove('d-none');

        const esc = WDash.escapeHtml;
        const onPage = sources.reduce((sum, s) => sum + (s.count || 0), 0) || 1;

        body.innerHTML = sources.map((source) => {
            const share = Math.round((source.count || 0) / onPage * 100);
            const count = Number(source.total || 0).toLocaleString();
            const total = source.failed ? 'no answer'
                : (source.exact === false ? '&ge; ' + count : count + ' matched');
            return '<div class="px-2 py-2 border-bottom">' +
                '<div class="d-flex justify-content-between align-items-center">' +
                    '<span class="text-truncate" style="font-size:.78rem">' +
                        (source.failed
                            ? '<i class="fas fa-triangle-exclamation text-danger me-1"></i>'
                            : '') +
                        esc(source.name) +
                    '</span>' +
                    '<span class="badge bg-secondary">' + WDash.count(source.count) + '</span>' +
                '</div>' +
                '<div class="progress mt-1" style="height:3px">' +
                    '<div class="progress-bar ' +
                        (source.failed ? 'bg-danger' : 'bg-info') +
                        '" style="width:' + (source.failed ? 100 : share) + '%"></div>' +
                '</div>' +
                '<small class="' + (source.failed ? 'text-danger' : 'text-muted') +
                    '" style="font-size:.68rem">' + total + '</small>' +
            '</div>';
        }).join('');
    }

    async loadFieldStats() {
        var container = document.getElementById('fieldStatsContent');
        if (!container) { console.warn('fieldStatsContent not found'); return; }

        container.innerHTML = '<div class="text-center py-3"><div class="spinner-border spinner-border-sm text-info"></div></div>';

        // Build same params as current search
        var params = new URLSearchParams();
        var queryInput = document.getElementById('query');
        params.append('q', queryInput ? queryInput.value || '*' : '*');

        // The same source the results came from. Without it the sidebar
        // answered from the default source whatever the page was showing:
        // Elasticsearch statistics beside VictoriaLogs rows, with service
        // names that appear nowhere in the results above them.
        var sourceSelect = document.getElementById('sourceSelect');
        if (sourceSelect && sourceSelect.value) {
            params.append('source', sourceSelect.value);
        }

        var timeRange = document.getElementById('timeRange');
        if (timeRange && timeRange.value && timeRange.value !== 'custom') {
            var now = new Date();
            var offsets = {
                '15m': 15*60*1000, '1h': 60*60*1000, '6h': 6*60*60*1000,
                '24h': 24*60*60*1000, '7d': 7*24*60*60*1000
            };
            var offset = offsets[timeRange.value];
            if (offset) {
                params.append('start_time', new Date(now.getTime() - offset).toISOString());
                params.append('end_time', now.toISOString());
            }
        } else if (timeRange && timeRange.value === 'custom') {
            var startEl = document.getElementById('startTime');
            var endEl = document.getElementById('endTime');
            if (startEl && startEl.value) params.append('start_time', new Date(startEl.value).toISOString());
            if (endEl && endEl.value) params.append('end_time', new Date(endEl.value).toISOString());
        }

        try {
            var response = await fetch('/api/field-stats?' + params.toString());
            var data = await response.json();
            console.log('Field stats response:', data);
            // A failure is said as one. The status went unread, and a 503
            // was drawn as "No field data available" beside the results.
            if (!response.ok || data.error) {
                container.innerHTML = '<div class="p-2 text-warning"><small>' +
                    '<i class="fas fa-triangle-exclamation"></i> Field statistics ' +
                    'could not be loaded: ' + WDash.escapeHtml(data.error ||
                        ('HTTP ' + response.status)) + '</small></div>';
                return;
            }
            this.renderFieldStats(data);
        } catch (e) {
            console.error('Field stats error:', e);
            container.innerHTML = '<div class="p-2 text-muted"><small>Failed to load stats</small></div>';
        }
    }

    renderFieldStats(data) {
        const container = document.getElementById('fieldStatsContent');
        if (!container) return;

        const esc = WDash.escapeHtml;
        const attr = (v) => String(v).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
        let html = '';

        // A source that cannot answer is not a source with nothing to say.
        // "No field data available" beside a page full of logs reads as a
        // bug in WDash; the reason reads as a property of the backend.
        if (data.unsupported) {
            container.innerHTML =
                '<div class="p-2 text-muted"><small>' +
                '<i class="fas fa-circle-info"></i> ' + esc(data.reason ||
                    'This source does not provide field statistics.') +
                '</small></div>';
            return;
        }

        // A merged view where not every source could contribute. Said above
        // the numbers rather than instead of them: the counts are real, they
        // just do not cover everything on screen.
        if (data.partial && (data.missing_sources || []).length) {
            html += '<div class="px-2 py-2 border-bottom text-muted" ' +
                'style="font-size:.7rem">' +
                '<i class="fas fa-circle-info"></i> Counts exclude ' +
                data.missing_sources.map(esc).join(', ') +
                ', which cannot report field statistics.</div>';
        }
        // And the members that can, but did not answer this time.
        if ((data.failed_sources || []).length) {
            html += '<div class="px-2 py-2 border-bottom text-warning" ' +
                'style="font-size:.7rem">' +
                '<i class="fas fa-triangle-exclamation"></i> Counts exclude ' +
                data.failed_sources.map(esc).join(', ') +
                ', whose statistics could not be read.</div>';
        }
        // What the counts are short of. A backend answers a search from the
        // shards that replied and says so in the answer; the numbers here are
        // real, and what they cover is not what the page asked for. Said
        // above them rather than instead of them.
        (data.warnings || []).forEach(warning => {
            html += '<div class="px-2 py-2 border-bottom text-warning" ' +
                'style="font-size:.7rem">' +
                '<i class="fas fa-triangle-exclamation"></i> ' +
                esc(warning) + '</div>';
        });

        (data.fields || []).forEach(stat => {
            if (!stat.values || !stat.values.length) return;
            const label = stat.field.charAt(0).toUpperCase() +
                          stat.field.slice(1).replace(/_/g, ' ');
            const safeId = stat.field.replace(/[^a-zA-Z0-9_-]/g, '_');

            html += '<div class="field-stat-group">';
            html += '<div class="field-stat-header" data-bs-toggle="collapse" data-bs-target="#fs-' + safeId + '">';
            html += '<i class="fas fa-caret-down me-1"></i>' + esc(label) + '</div>';
            html += '<div class="collapse show" id="fs-' + safeId + '">';
            stat.values.forEach(item => {
                // A record with no value for the field is a real bucket, and
                // a blank row with a number beside it looks like a rendering
                // fault. Named rather than dropped: "7 records have no env"
                // is worth knowing.
                const shown = (item.value === '' || item.value === null)
                    ? '(none)' : item.value;
                const filterQ = stat.field + ':' + WDash.quoted(item.value);
                html += '<div class="field-stat-item">' +
                    '<span class="field-stat-value text-truncate" title="' + attr(shown) + '">' +
                        esc(shown) + '</span>' +
                    '<span class="field-stat-count">' + WDash.count(item.count).toLocaleString() + '</span>' +
                    '<span class="field-stat-filter field-action" data-sidebar-filter="' +
                        attr(filterQ) + '" title="Filter">&#128269;</span>' +
                    '</div>';
            });
            html += '</div></div>';
        });

        container.innerHTML = html ||
            '<div class="p-2 text-muted"><small>No field data available</small></div>';

        container.querySelectorAll('[data-sidebar-filter]').forEach(el => {
            el.addEventListener('click', () => this._applyFieldFilter(el.dataset.sidebarFilter));
        });
    }

    // ---- which fields the sidebar counts ------------------------------
    //
    // The source discovers what its mapping offers and shows the first ten
    // BY NAME, which on a cluster whose fields begin with punctuation is
    // ten fields nobody asked for. This is where somebody says otherwise.
    //
    // The offer is fetched ONCE per opening rather than with every search:
    // it reads the whole mapping and does not change between two searches
    // a minute apart.

    _setupFieldStatsPicker() {
        // Both halves are reported, because a control that silently does
        // nothing is the one failure nobody can describe. A deployment said
        // "the button does nothing" and the console held no clue at all:
        // this returns early when the button is absent, and the click
        // handler would have thrown on a missing panel — neither of which
        // said so.
        const button = document.getElementById('fieldStatsPick');
        const panel = document.getElementById('fieldStatsPicker');
        if (!button) {
            if (panel) {
                console.warn('WDash: the field picker panel is on the page ' +
                             'but its button is not, so nothing can open it.');
            }
            return;
        }
        if (!panel) {
            console.warn('WDash: the field picker button is on the page but ' +
                         'its panel (#fieldStatsPicker) is not, so clicking ' +
                         'it cannot do anything. The two are rendered ' +
                         'together; a page with one and not the other is a ' +
                         'stale template or a partial copy of it.');
            button.setAttribute('disabled', 'disabled');
            button.title = 'Unavailable: this page is missing the picker.';
            return;
        }
        console.log('WDash: field picker wired up.');

        // A dialog, opened through Bootstrap so it gets the backdrop, the
        // focus trap and Escape without any of that being written here.
        button.addEventListener('click', () => {
            // Forgotten on each opening, so it always starts from what is
            // actually stored rather than from ticks somebody abandoned
            // and then dismissed.
            this._ticked = null;
            const filter = document.getElementById('fieldStatsFilter');
            if (filter) { filter.value = ''; }
            this._statsModal().show();
            this._loadStatsFieldOffer();
        });

        const filter = document.getElementById('fieldStatsFilter');
        if (filter) {
            filter.addEventListener('input', () => {
                const wanted = filter.value.trim().toLowerCase();
                let anything = false;
                document.querySelectorAll('#fieldStatsOptions .form-check')
                    .forEach(row => {
                        const name = row.dataset.field || '';
                        // A ticked field never hides: a filter that removes
                        // it from view while leaving it in the saved set is
                        // a save that silently keeps what is off screen.
                        const ticked = row.querySelector('input').checked;
                        const matches = !wanted || name.toLowerCase().includes(wanted);
                        anything = anything || matches;
                        // The COLUMN, not the row inside it. The list is a
                        // two-column grid: hiding the row leaves its cell
                        // holding the space, so filtering a long list drew
                        // as many blank gaps as it hid names.
                        (row.closest('.col') || row).classList.toggle(
                            'd-none', !ticked && !matches);
                    });

                // Nothing on this page matches, and the page holds a cut
                // of the mapping — so ask the server, which searches the
                // whole of it. Without this the filter can only narrow
                // what the cut already let through, which is the fault the
                // picker exists to fix, one level up.
                //
                // `_showingSearch` matters as much as the cut: once a
                // search has replaced the list, what is on screen is one
                // answer and not the offer, so the next word has to go to
                // the server whether or not THAT answer was cut. Without
                // it the panel got stuck inside the previous search — four
                // rows, and no word could reach past them.
                if (!wanted) {
                    if (this._showingSearch) { this._searchServerSide(''); }
                    return;
                }
                if (!anything && (this._offerWasCut || this._showingSearch)) {
                    this._searchServerSide(wanted);
                }
            });
        }

        const save = document.getElementById('fieldStatsSave');
        if (save) { save.addEventListener('click', () => this._saveStatsFields()); }
        const clear = document.getElementById('fieldStatsClear');
        if (clear) { clear.addEventListener('click', () => this._saveStatsFields([])); }

        // No probe on load. The button is rendered only for somebody who
        // may save the choice, which the template already knows.
    }

    _statsModal() {
        // One instance, kept: `new bootstrap.Modal(el)` twice on one element
        // leaves two sets of handlers and a backdrop that outlives the
        // dialog. `getOrCreateInstance` is the one that does not.
        return bootstrap.Modal.getOrCreateInstance(
            document.getElementById('fieldStatsPicker'));
    }

    //: The last search sent, so a keystroke that arrives while one is in
    //: flight replaces it rather than racing it: two answers to two
    //: prefixes can arrive in either order, and the loser paints a list
    //: for a word nobody is still typing.
    _searchServerSide(wanted) {
        this._offerSearch = wanted;
        clearTimeout(this._offerSearchTimer);
        this._offerSearchTimer = setTimeout(() => {
            if (this._offerSearch !== wanted) { return; }
            this._loadStatsFieldOffer({search: wanted});
        }, 250);
        return this._offerSearchTimer;
    }

    _statsSourceName() {
        const select = document.getElementById('sourceSelect');
        return select && select.value ? select.value : '';
    }

    async _loadStatsFieldOffer(options) {
        const search = (options && options.search) || '';
        const options_el = document.getElementById('fieldStatsOptions');
        const note = document.getElementById('fieldStatsPickerNote');
        const params = new URLSearchParams();
        const source = this._statsSourceName();
        if (source) { params.append('source', source); }
        if (search) { params.append('q', search); }

        if (options_el) {
            options_el.innerHTML = '<div class="text-center py-2">' +
                '<div class="spinner-border spinner-border-sm text-info"></div></div>';
        }
        let data;
        try {
            const response = await fetch(
                '/api/field-stats/fields?' + params.toString());
            data = await response.json();
            if (!response.ok || data.error) {
                options_el.innerHTML = '<div class="text-warning" ' +
                    'style="font-size:.75rem">' + WDash.escapeHtml(
                        data.error || ('HTTP ' + response.status)) + '</div>';
                return;
            }
        } catch (e) {
            options_el.innerHTML = '<div class="text-muted" ' +
                'style="font-size:.75rem">The field list could not be ' +
                'loaded.</div>';
            return;
        }

        // Remembered so the filter box knows whether looking further is
        // worth a request: on an offer that holds the whole mapping, a word
        // that matches nothing here matches nothing anywhere.
        //
        // Only from the UNSEARCHED offer. A search that happens to answer
        // completely would otherwise clear the flag and strand the panel
        // inside its own result.
        if (!search) { this._offerWasCut = !!data.partial; }
        this._showingSearch = !!search;
        this._renderStatsFieldOffer(data);
        if (note) {
            const lines = [];
            if (data.unsupported && data.reason) { lines.push(data.reason); }
            (data.warnings || []).forEach(w => lines.push(w));
            if (!data.chosen || !data.chosen.length) {
                lines.push("Nothing chosen: this source shows the first ten " +
                           "field names it finds.");
            }
            if (search) {
                lines.unshift(data.fields && data.fields.length
                    ? 'Showing the ' + data.fields.length + ' field' +
                      (data.fields.length === 1 ? '' : 's') +
                      ' matching "' + search + '".'
                    : 'No field in this source\'s mapping matches "' +
                      search + '".');
            }
            note.innerHTML = lines.map(WDash.escapeHtml).join('<br>');
        }
    }

    _renderStatsFieldOffer(data) {
        const container = document.getElementById('fieldStatsOptions');
        if (!container) { return; }
        // Ticks live here and not in the DOM, because a search REPLACES the
        // list: ticking four fields, searching for a fifth and saving used
        // to store only the fifth, and the four went without a word. Seeded
        // from what is stored the first time the panel is filled.
        if (!this._ticked) { this._ticked = new Set(data.chosen || []); }
        const chosen = this._ticked;
        const names = data.fields || [];
        if (!names.length) {
            container.innerHTML = '<div class="text-muted" ' +
                'style="font-size:.75rem">This source maps no field that can ' +
                'be counted.</div>';
            return;
        }
        // Chosen first, so that the ones in force are visible without
        // scrolling a list of three hundred.
        const ordered = names.slice().sort((a, b) => {
            const picked = (chosen.has(b) ? 1 : 0) - (chosen.has(a) ? 1 : 0);
            return picked || a.localeCompare(b);
        });
        container.innerHTML = ordered.map((name, index) => {
            const id = 'fs-pick-' + index;
            // `col` because the container is a two-column row at md and up.
            // The name is the label's title as well as its text: these are
            // long enough to truncate, and a truncated name somebody cannot
            // read in full is a name they cannot choose between.
            return '<div class="col"><div class="form-check py-1" ' +
                'data-field="' + WDash.escapeAttr(name) + '">' +
                '<input class="form-check-input" type="checkbox" id="' + id +
                    '"' + (chosen.has(name) ? ' checked' : '') + '>' +
                '<label class="form-check-label text-truncate d-block" ' +
                    'for="' + id + '" title="' + WDash.escapeAttr(name) +
                    '" style="font-size:.8rem">' + WDash.escapeHtml(name) +
                '</label></div></div>';
        }).join('');

        container.querySelectorAll('input[type="checkbox"]').forEach(box => {
            box.addEventListener('change', () => {
                const name = box.closest('.form-check').dataset.field;
                if (box.checked) { this._ticked.add(name); }
                else { this._ticked.delete(name); }
                this._showChosenCount();
            });
        });
        this._showChosenCount();
    }

    _showChosenCount() {
        // How many are ticked, including the ones a search has scrolled
        // out of view: the whole reason the ticks live off the DOM is that
        // what is on screen is not the choice.
        const label = document.getElementById('fieldStatsChosenCount');
        if (!label) { return; }
        const count = (this._ticked || new Set()).size;
        label.textContent = count
            ? count + (count === 1 ? ' field chosen' : ' fields chosen')
            : 'nothing chosen';
    }

    async _saveStatsFields(override) {
        // From the remembered set, not from the rows on screen: a search
        // has replaced them, and what is on screen is one answer rather
        // than the whole choice.
        const chosen = override || Array.from(this._ticked || []);
        const note = document.getElementById('fieldStatsPickerNote');
        try {
            const response = await fetch('/api/field-stats/fields', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({source: this._statsSourceName(),
                                      fields: chosen}),
            });
            const data = await response.json();
            if (!response.ok || data.error) {
                if (note) {
                    note.innerHTML = '<span class="text-warning">' +
                        WDash.escapeHtml(data.error ||
                            ('HTTP ' + response.status)) + '</span>';
                }
                return;
            }
            WDash.showNotification(
                chosen.length
                    ? 'The sidebar now counts ' + chosen.length +
                      (chosen.length === 1 ? ' field.' : ' fields.')
                    : 'The sidebar shows what this source offers.',
                'success');
            this._statsModal().hide();
            this.loadFieldStats();
        } catch (e) {
            if (note) {
                note.innerHTML = '<span class="text-warning">The choice ' +
                    'could not be saved.</span>';
            }
        }
    }

    _setupSavedSearches() {
        var self = this;
        this._loadSavedSearches();

        var saveBtn = document.getElementById('saveSearchBtn');
        if (saveBtn) {
            saveBtn.addEventListener('click', function() {
                var nameInput = document.getElementById('saveSearchName');
                var name = nameInput ? nameInput.value.trim() : '';
                if (!name) { WDash.showNotification('Enter a name for the search', 'warning'); return; }
                self._saveCurrentSearch(name);
                if (nameInput) nameInput.value = '';
            });
        }

        var nameInput = document.getElementById('saveSearchName');
        if (nameInput) {
            nameInput.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    e.stopPropagation();
                    saveBtn.click();
                }
            });
        }
    }

    async _loadSavedSearches() {
        var listEl = document.getElementById('savedSearchList');
        if (!listEl) return;
        try {
            var response = await fetch('/api/saved-searches');
            var searches = await response.json();
            if (!response.ok) {
                // The server composes a sentence for this — "Your saved
                // searches could not be read, so none can be listed" — and
                // it reached nobody. `searches` is then an error OBJECT,
                // `searches.length` is undefined, undefined is falsy, and
                // every answer landed in the empty branch below: a 503 that
                // could not read the file and a 403 the role may not have
                // both drew "No saved searches yet".
                //
                // The comment below is about exactly this distinction on
                // the server's side. It has one here too now.
                listEl.innerHTML = '<span class="dropdown-item-text text-danger">' +
                    '<small>' + WDash.escapeHtml(
                        (searches && searches.error)
                        || 'Your saved searches could not be listed.') +
                    '</small></span>';
                return;
            }
            if (!searches.length) {
                // "No saved searches yet" and "they are in a file this
                // installation stopped reading" are different answers, and
                // the API cannot tell them apart: it returns [] for both.
                // The page carries what the server found, so an empty list
                // that is really an unmigrated one says so.
                var leftBehind = listEl.dataset.leftBehind;
                listEl.innerHTML = '<span class="dropdown-item-text text-muted"><small>' +
                    (leftBehind ? WDash.escapeHtml(leftBehind) + '. Nothing has been deleted.'
                                : 'No saved searches yet') + '</small></span>';
                return;
            }
            var self = this;
            var html = '';
            searches.forEach(function(s) {
                html += '<div class="d-flex align-items-center px-2 py-1 saved-search-item">';
                html += '<a href="#" class="dropdown-item py-1 px-2 flex-grow-1 text-truncate saved-search-apply" data-query="' + s.query.replace(/&/g,'&amp;').replace(/"/g,'&quot;') + '" data-time="' + WDash.escapeAttr(s.time_range) + '">';
                html += '<small>' + WDash.escapeHtml(s.name) + '</small><br><code style="font-size:0.7rem" class="text-muted">' + WDash.escapeHtml(s.query) + '</code>';
                html += '</a>';
                html += '<button class="btn btn-sm btn-link text-danger p-0 ms-1 saved-search-delete" data-id="' + WDash.escapeAttr(s.id) + '" title="Delete"><i class="fas fa-trash-alt" style="font-size:0.7rem"></i></button>';
                html += '</div>';
            });
            listEl.innerHTML = html;

            listEl.querySelectorAll('.saved-search-apply').forEach(function(el) {
                el.addEventListener('click', function(e) {
                    e.preventDefault();
                    self._applySavedSearch(el.dataset.query, el.dataset.time);
                });
            });
            listEl.querySelectorAll('.saved-search-delete').forEach(function(el) {
                el.addEventListener('click', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    self._deleteSavedSearch(el.dataset.id);
                });
            });
        } catch (e) {
            listEl.innerHTML = '<span class="dropdown-item-text text-muted"><small>Failed to load</small></span>';
        }
    }

    async _saveCurrentSearch(name) {
        var queryInput = document.getElementById('query');
        var timeRange = document.getElementById('timeRange');
        var query = queryInput ? queryInput.value.trim() : '*';
        var tr = timeRange ? timeRange.value : '1h';
        if (tr === 'custom') tr = '1h';

        try {
            var response = await fetch('/api/saved-searches', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name: name, query: query, time_range: tr})
            });
            if (response.ok) {
                WDash.showNotification('Search saved: ' + name, 'success');
                this._loadSavedSearches();
            } else {
                var data = await response.json();
                WDash.showNotification(data.error || 'Failed to save', 'danger');
            }
        } catch (e) {
            WDash.showNotification('Failed to save search', 'danger');
        }
    }

    _applySavedSearch(query, timeRange) {
        var queryInput = document.getElementById('query');
        var timeRangeSelect = document.getElementById('timeRange');
        if (queryInput) queryInput.value = query;
        if (timeRangeSelect && timeRange) {
            timeRangeSelect.value = timeRange;
            timeRangeSelect.dispatchEvent(new Event('change'));
        }
        this.currentPage = 0;
        this.currentSearchAfter = null;
        this.searchAfterStack = [];
        this.performSearch();
    }

    async _deleteSavedSearch(id) {
        try {
            var response = await fetch('/api/saved-searches/' + encodeURIComponent(id),
                                       {method: 'DELETE'});
            if (response.ok) {
                WDash.showNotification('Search deleted', 'success');
                this._loadSavedSearches();
                return;
            }
            // A refusal used to do nothing at all — no message, no change,
            // the row still in the list. `if (response.ok)` with no else,
            // and the catch below only fires on a network throw. So a 403
            // for somebody else's search, or a 503 from a store that could
            // not be written, looked exactly like a click that missed.
            // `_saveCurrentSearch` in this same class reads the body and
            // shows `data.error`; this is that.
            var body = await response.json().catch(() => null);
            WDash.showNotification(
                (body && body.error) || 'That saved search could not be '
                + 'deleted.', 'danger');
        } catch (e) {
            WDash.showNotification('Failed to delete', 'danger');
        }
    }

    showError(message, errorType, data = {}) {
        const errorDisplay = document.getElementById('errorDisplay');
        const errorAlert = document.getElementById('errorAlert');
        const errorContent = document.getElementById('errorContent');
        
        let alertClass = 'alert-danger';
        let icon = 'fas fa-exclamation-circle';
        
        // Customize alert based on error type
        switch (errorType) {
            case 'no_accessible_containers':
                alertClass = 'alert-warning';
                icon = 'fas fa-exclamation-triangle';
                break;
            case 'no_indices':
                alertClass = 'alert-info';
                icon = 'fas fa-info-circle';
                break;
            case 'invalid_query':
                alertClass = 'alert-warning';
                icon = 'fas fa-exclamation-triangle';
                break;
            case 'timeout':
                alertClass = 'alert-warning';
                icon = 'fas fa-clock';
                break;
        }
        
        errorAlert.className = `alert ${alertClass} alert-dismissible fade show`;
        
        // The message is the server's, and it can quote the query back — a
        // /logs?query= link put its own markup into this box.
        let content = `<h6><i class="${icon}"></i> ${this.getErrorTitle(errorType)}</h6>` +
            `<p>${WDash.escapeHtml(message)}</p>`;
        
        // Add helpful suggestions based on error type
        const suggestions = this.getErrorSuggestions(errorType, data);
        if (suggestions) {
            content += `<hr><div class="mb-0">${suggestions}</div>`;
        }
        
        errorContent.innerHTML = content;
        errorDisplay.classList.remove('d-none');
        
        // Clear results
        document.getElementById('logEntries').innerHTML = '';
        document.getElementById('resultsInfo').innerHTML = '';
        document.getElementById('pagination').innerHTML = '';
        // And everything else the last search drew. Three of the ids above
        // were cleared and four were not, so a refused search left the
        // previous one's histogram, source breakdown, warnings and field
        // statistics on screen — under a red box about a search that never
        // ran. Measured through the shipped bundle: a good search, then one
        // the server answered `invalid_query`, and the chart still read
        // "4,311 records across 2 intervals" with "lab-loki: did not
        // answer" beside it.
        //
        // `clearSearch` has done this since it was written and carries the
        // sentence naming this exact fault. Reused rather than copied: two
        // lists of ids drift, and this is what drifting looks like.
        this.clearLastAnswer();
    }

    /**
     * Everything a search drew apart from its rows.
     *
     * The chart, the per-source breakdown, the warnings and the field
     * statistics. Called from `clearSearch`, which empties the page on
     * purpose, and from `showError`, where leaving them is a description of
     * a search that is no longer there.
     */
    clearLastAnswer() {
        this.clearHistogram();
        ['sourceBreakdownCard', 'searchWarnings'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add('d-none');
        });
        const warnings = document.getElementById('searchWarnings');
        if (warnings) warnings.innerHTML = '';
        const stats = document.getElementById('fieldStatsContent');
        if (stats) {
            stats.innerHTML = '<div class="text-center py-3 text-muted"><small>' +
                'Run a search to see field stats</small></div>';
        }
    }

    hideError() {
        const errorDisplay = document.getElementById('errorDisplay');
        errorDisplay.classList.add('d-none');
    }

    getErrorTitle(errorType) {
        const titles = {
            'permission_denied': 'Access Denied',
            'no_accessible_containers': 'No Accessible Indices',
            'no_indices': 'No Indices Found',
            'index_access_denied': 'Index Access Denied',
            'elasticsearch_connection': 'Connection Error',
            'invalid_query': 'Invalid Search Query',
            'invalid_parameters': 'Invalid Parameters',
            'timeout': 'Search Timeout',
            'search_error': 'Search Error',
            'network_error': 'Network Error'
        };
        return titles[errorType] || 'Error';
    }

    getErrorSuggestions(errorType, data = {}) {
        switch (errorType) {
            case 'no_accessible_containers':
                let suggestions = '<strong>What you can do:</strong><ul class="mt-2 mb-0">';
                suggestions += '<li>Contact your administrator to request access to log indices</li>';
                if (data.available_indices && data.available_indices.length > 0) {
                    // Loki and VictoriaLogs container names are label values,
                    // and a label value can be anything.
                    suggestions += `<li>Available indices: <code>${WDash.escapeHtml(data.available_indices.slice(0, 5).join(', '))}</code>${data.available_indices.length > 5 ? '...' : ''}</li>`;
                } else if (data.total_containers) {
                    // Everybody but an administrator is told how many, not
                    // which: the names are what the boundary holds back.
                    suggestions += `<li>${WDash.count(data.total_containers)} exist that your role cannot read</li>`;
                }
                suggestions += '<li>Ask to be assigned a role with broader permissions</li></ul>';
                return suggestions;
                
            case 'invalid_query':
                return '<strong>Query examples:</strong><ul class="mt-2 mb-0"><li><code>level:ERROR</code> - Show error logs</li><li><code>service:api AND status:500</code> - API errors</li><li><code>message:"database connection"</code> - Specific message</li></ul>';
                
            case 'timeout':
                return '<strong>Try:</strong><ul class="mt-2 mb-0"><li>Use a more specific search query</li><li>Narrow the time range</li><li>Search fewer indices</li></ul>';
                
            case 'elasticsearch_connection': {
                // Whichever backend this source is. /api/search answers with
                // this type for Loki and VictoriaLogs too, so the box that
                // says "Unable to connect to loki-down" went on to advise
                // going and checking Elasticsearch.
                const check = data.source
                    ? `Check if ${WDash.escapeHtml(data.source)} is running and accessible`
                    : 'Check if the log source is running and accessible';
                return `<strong>Possible solutions:</strong><ul class="mt-2 mb-0"><li>${check}</li><li>Verify network connectivity</li><li>Contact your system administrator</li></ul>`;
            }
                
            case 'no_indices':
                return '<strong>This might mean:</strong><ul class="mt-2 mb-0"><li>No logs have been ingested yet</li><li>Elasticsearch is empty</li><li>Log shipping is not configured</li></ul>';
                
            default:
                return null;
        }
    }

    /**
     * Volume over time, stacked by severity.
     *
     * The counts come back on the SAME response as the records — a separate
     * request would double the round trips for something the search already
     * had to scan.
     */
    /** Take the chart away, and the bars a theme switch would draw again. */
    clearHistogram() {
        const card = document.getElementById('histogramCard');
        if (card) card.classList.add('d-none');
        if (this.histogramChart) this.histogramChart.destroy();
        this.histogramChart = null;
        this.histogramData = null;
    }

    renderHistogram(data) {
        const card = document.getElementById('histogramCard');
        const canvas = document.getElementById('logHistogram');
        if (!card || !canvas || typeof Chart === 'undefined') return;

        const buckets = data.histogram || [];
        if (!buckets.length) {
            this.clearHistogram();
            return;
        }
        card.classList.remove('d-none');
        // Kept so a theme switch can draw the same bars in the new colours.
        this.histogramData = data;

        // Fixed order and colour so a severity always looks the same, and the
        // eye can compare two searches without re-reading the legend.
        //
        // From the palette, and the palette the REST of the product uses.
        // These were Bootstrap's own — `#dc3545` for ERROR against the
        // `#ff7b72` an ERROR badge is painted with two inches above it, and
        // `#ffc107` for WARN against `#f2cc60`. Two vocabularies for one
        // fact, which is the thing `test_down_is_the_same_red_the_log_levels
        // _use` exists to prevent in the stylesheet and could not see here.
        const LEVELS = [
            ['FATAL', '--fill-red-strong'], ['ERROR', '--fill-red'],
            ['WARN', '--fill-yellow'], ['INFO', '--fill-blue'],
            ['DEBUG', '--fill-purple'], ['TRACE', '--text-muted'],
            ['UNSPECIFIED', '--border-strong'],
        ];
        const present = LEVELS.filter(([name]) =>
            buckets.some(b => (b.by_severity || {})[name]));

        const labels = buckets.map(b => new Date(b.timestamp || b.key));
        const datasets = (present.length ? present : [['count', '--fill-blue']]).map(([name, token]) => ({
            label: name,
            backgroundColor: paletteColour(token),
            data: buckets.map(b => present.length
                ? ((b.by_severity || {})[name] || 0)
                : b.count),
            borderWidth: 0,
        }));

        if (this.histogramChart) this.histogramChart.destroy();
        this.histogramChart = new Chart(canvas, {
            type: 'bar',
            data: { labels: labels.map(d => d.toLocaleString()), datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                // The axis and legend text from the palette too. Left to
                // Chart.js they were its built-in #666, which the contrast
                // suite cannot see on a canvas: 2.2:1 on the dark page.
                scales: {
                    x: { stacked: true,
                         ticks: { maxTicksLimit: 8, font: { size: 9 },
                                  color: paletteColour('--text-muted') },
                         grid: { display: false } },
                    y: { stacked: true,
                         ticks: { maxTicksLimit: 4, font: { size: 9 },
                                  color: paletteColour('--text-muted') },
                         grid: { color: paletteColour('--grid-faint') } },
                },
                plugins: {
                    legend: { labels: { boxWidth: 10, font: { size: 10 },
                                        color: paletteColour('--text-primary') } },
                    tooltip: { mode: 'index', intersect: false },
                },
                onClick: (evt, items) => {
                    if (!items.length) return;
                    this.zoomToBucket(buckets, items[0].index);
                },
            },
        });

        const total = buckets.reduce((n, b) => n + b.count, 0);
        const busiest = buckets.reduce((a, b) => (b.count > a.count ? b : a), buckets[0]);
        document.getElementById('histogramSummary').textContent =
            `${total.toLocaleString()} records across ${buckets.length} intervals · ` +
            `busiest ${new Date(busiest.timestamp || busiest.key).toLocaleString()} ` +
            `(${busiest.count.toLocaleString()})`;
    }

    /**
     * Clicking a bar narrows the search to that interval — the fastest way to
     * get from "something spiked" to the records that caused it.
     */
    zoomToBucket(buckets, index) {
        const start = new Date(buckets[index].timestamp || buckets[index].key);
        const next = buckets[index + 1];
        const end = next ? new Date(next.timestamp || next.key)
                         : new Date(start.getTime() + 60000);

        const pad = (n) => String(n).padStart(2, '0');
        const local = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
                             `${pad(d.getHours())}:${pad(d.getMinutes())}`;

        const timeRange = document.getElementById('timeRange');
        if (timeRange) {
            timeRange.value = 'custom';
            timeRange.dispatchEvent(new Event('change'));
        }
        const startEl = document.getElementById('startTime');
        const endEl = document.getElementById('endTime');
        if (startEl) startEl.value = local(start);
        if (endEl) endEl.value = local(end);

        this.currentPage = 0;
        this.currentSearchAfter = null;
        this.searchAfterStack = [];
        this.performSearch();
        WDash.showNotification('Zoomed to ' + start.toLocaleString(), 'info');
    }

    displayResults(data) {
        // The server knows how many sources are configured; the client only
        // decides how to draw it.
        this.showSources = Boolean(data.multiple_sources);
        this.showSearchWarnings(data);

        this.totalResults = WDash.count(data.total);
        const logEntries = document.getElementById('logEntries');
        const resultsInfo = document.getElementById('resultsInfo');
        const emptyState = document.getElementById('emptyState');
        
        emptyState.classList.add('d-none');
        
        // The cursor for the next page, or none. Kept only when there was
        // one, the last answer's stayed — and a source that cannot page (a
        // merged search, VictoriaLogs) left none, so Next asked for page one
        // again and labelled it page two.
        this.currentSearchAfter = data.cursor || null;
        // How many sources this answer came from, so the sentence about not
        // being able to page can name the right thing. A merge cannot page
        // even when every member could; blaming "this source" for it sends
        // somebody to look at a backend that is fine.
        this.answeredBy = (data.sources || []).length;
        
        const startResult = this.currentPage * this.pageSize + 1;
        const endResult = Math.min(startResult + data.records.length - 1, this.totalResults);
        
        // "Showing 1-0 of 0" was the empty answer's line.
        let infoText = data.records.length
            ? `Showing ${startResult}-${endResult} of ${this.totalResults.toLocaleString()} results`
            : `Showing 0 of ${this.totalResults.toLocaleString()} results`;
        const took = WDash.count(data.took_ms);
        if (took) {
            infoText += ` (${took}ms)`;
        }
        if (data.partial) {
            infoText += ' <span class="badge bg-warning">Timed Out</span>';
        }
        if (data.accessible_containers) {
            infoText += ` from ${data.accessible_containers.length} indices`;
        }
        
        resultsInfo.innerHTML = infoText;
        logEntries.innerHTML = '';
        
        // The server sends the histogram with the first page only: it covers
        // the whole window, so a later page keeps the first page's chart
        // rather than hiding it for the want of one.
        if (this.currentPage === 0) this.renderHistogram(data);
        // Before any return: an empty answer left the last search's pages.
        this.updatePagination();
        
        if (data.records.length === 0) {
            if (this.currentPage === 0) {
                emptyState.classList.remove('d-none');
            }
            return;
        }
        
        data.records.forEach(record => {
            logEntries.appendChild(this.createLogEntry(record));
        });
    }

    createLogEntry(record) {
        const div = document.createElement('div');
        const severity = record.severity_text || record.severity || 'INFO';
        const cssLevel = (record.severity || 'INFO').toLowerCase();
        const service = record.service || 'unknown';
        const host = (record.resource || {}).host;
        const message = record.body || '';

        div.className = `log-entry ${cssLevel} fade-in`;
        div.style.cursor = 'pointer';
        div.title = 'Click to view full log details';

        const preview = WDash.formatMessagePreview(message);
        const multilineBadge = preview.lineCount > 1
            ? `<span class="log-multiline-badge" data-toggle-expand>+${preview.lineCount - 1} lines</span>`
            : '';

        // Log content is untrusted: service, host and container names come from
        // the document too and must not reach the DOM unescaped.
        const esc = WDash.escapeHtml;
        const container = (record.ref || '').split(':')[1] || '';
        const attrs = record.attributes || {};

        div.innerHTML = `
            <div class="d-flex justify-content-between align-items-start mb-2">
                <div>
                    <span class="log-level ${WDash.levelClass(record)}">${esc(severity)}</span>
                    <span class="ms-2 fw-bold">${esc(service)}</span>
                    ${host ? `<span class="ms-2 text-muted">${esc(host)}</span>` : ''}
                    ${record.trace_id ? `<span class="badge bg-info ms-2" title="Correlated with a trace"><i class="fas fa-project-diagram"></i></span>` : ''}
                </div>
                <span class="timestamp">${esc(WDash.formatTimestamp(record.timestamp))}</span>
            </div>
            <div class="log-message">
                <pre class="mb-0 text-monospace">${esc(message)}</pre>
                ${multilineBadge}
            </div>
            <div class="mt-2">
                <small class="text-muted">
                    ${this.showSources && record.source
                        ? `<span class="badge bg-secondary-subtle text-secondary me-1"
                                 title="Answered by the '${WDash.escapeAttr(record.source)}' source"
                                 style="font-size:.65rem">${esc(record.source)}</span>`
                        : ''}
                    Index: ${esc(container)}
                    ${attrs.request_id ? ` | Request: ${esc(attrs.request_id)}` : ''}
                    ${attrs.duration_ms ? ` | Duration: ${esc(attrs.duration_ms)}ms` : ''}
                </small>
            </div>
        `;

        const expandBtn = div.querySelector('[data-toggle-expand]');
        if (expandBtn) {
            expandBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                const pre = div.querySelector('pre');
                pre.classList.toggle('expanded');
                expandBtn.textContent = pre.classList.contains('expanded')
                    ? 'Collapse'
                    : `+${preview.lineCount - 1} lines`;
            });
        }

        div.addEventListener('click', () => this.showLogModal(record));
        return div;
    }


    showLogModal(record) {
        const modal = document.getElementById('logModal');
        const modalTitle = document.getElementById('logModalTitle');
        const modalBody = document.getElementById('logModalBody');
        if (!modal || !modalTitle || !modalBody) return;

        const esc = WDash.escapeHtml;
        const severity = record.severity_text || record.severity || 'INFO';
        const service = record.service || 'unknown';
        const message = record.body || '';

        modalTitle.innerHTML =
            '<span class="log-level ' + WDash.levelClass(record) +
                ' me-2">' + esc(severity) + '</span>' +
            '<strong>' + esc(service) + '</strong>' +
            '<small class="text-muted ms-2">' + esc(WDash.formatTimestamp(record.timestamp)) +
            '</small>';

        const formattedMessage = WDash.formatMessageFull(message);
        const messageLabel = WDash.isJson(message) ? 'JSON'
            : WDash.isStackTrace(message) ? 'Stack Trace' : 'Message';
        const prettyJson = JSON.stringify(record, null, 2);

        // A concrete payoff of the neutral model: the log-to-trace link is now
        // an explicit part of the data model rather than something to guess at.
        const traceLink = record.trace_id
            ? '<a class="btn btn-sm btn-outline-info" target="_blank" href="/traces?trace_id=' +
              encodeURIComponent(record.trace_id) + '">' +
              '<i class="fas fa-project-diagram"></i> View trace</a> '
            : '';

        modalBody.innerHTML =
            '<div class="log-details-container">' +
                '<div class="d-flex justify-content-between align-items-center mb-3">' +
                    '<div>' +
                        '<button class="btn btn-sm btn-outline-primary active" id="tabFields"><i class="fas fa-table"></i> Fields</button> ' +
                        '<button class="btn btn-sm btn-outline-secondary" id="tabMessage"><i class="fas fa-align-left"></i> ' + messageLabel + '</button> ' +
                        '<button class="btn btn-sm btn-outline-secondary" id="tabRawJson"><i class="fas fa-code"></i> JSON</button> ' +
                        '<button class="btn btn-sm btn-outline-secondary" id="tabSource"><i class="fas fa-database"></i> Raw</button>' +
                    '</div>' +
                    '<div>' + traceLink +
                        '<button class="btn btn-sm btn-outline-primary" id="copyLogButton"><i class="fas fa-copy"></i> Copy</button>' +
                    '</div>' +
                '</div>' +
                '<div id="fieldsView"><div class="field-table-container">' + this._renderFieldTable(record) + '</div></div>' +
                '<div id="messageView" class="modal-message-block d-none"><pre class="mb-0" style="background:none;border:none;padding:0;box-shadow:none;">' + formattedMessage + '</pre></div>' +
                '<div id="jsonView" class="d-none">' +
                    '<div class="text-muted mb-2" style="font-size:.75rem">' +
                        '<i class="fas fa-info-circle"></i> The record as WDash understands it.' +
                    '</div>' +
                    '<pre class="json-display"><code>' + WDash.highlightJson(prettyJson) + '</code></pre></div>' +
                '<div id="sourceView" class="d-none">' +
                    '<div class="text-muted mb-2" style="font-size:.75rem">' +
                        '<i class="fas fa-info-circle"></i> The document exactly as stored. ' +
                        'Fields WDash does not map are only visible here.' +
                    '</div>' +
                    '<pre class="json-display"><code id="sourceCode" class="text-muted">Loading&hellip;</code></pre></div>' +
            '</div>';

        // The record the detail, raw and context views are about. Their
        // requests name its source, and the context controls read it at the
        // moment they are clicked rather than holding the one they were
        // first bound for.
        this._openRecord = record;
        this._loadFullRecord(record.ref);
        this._setupModalTabs(record.ref);
        this._setupContextButtons();

        document.getElementById('copyLogButton').addEventListener('click', function() {
            // Copy what is on screen. Looking at the stored document and
            // getting the neutral record on the clipboard is a quiet trap:
            // you paste it into a ticket and the field you needed is gone.
            const source = document.getElementById('sourceCode');
            const showingRaw = !document.getElementById('sourceView').classList.contains('d-none');
            const payload = (showingRaw && source && source.dataset.loaded === 'true')
                ? source.textContent : prettyJson;
            navigator.clipboard.writeText(payload).then(function() {
                const btn = document.getElementById('copyLogButton');
                btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
                btn.classList.replace('btn-outline-primary', 'btn-success');
                setTimeout(function() {
                    const b = document.getElementById('copyLogButton');
                    if (b) { b.innerHTML = '<i class="fas fa-copy"></i> Copy'; b.classList.replace('btn-success', 'btn-outline-primary'); }
                }, 2000);
            }).catch(function() { WDash.showNotification('Failed to copy', 'danger'); });
        });

        new bootstrap.Modal(modal).show();
    }

    _renderFieldTable(record) {
        const rows = [this._fieldRow('ref', record.ref, true)];
        WDash.recordFields(record).forEach(([key, value]) => {
            rows.push(this._fieldRow(key, value, false));
        });
        return '<table class="table table-hover field-table table-dense mb-0">' +
            '<thead><tr><th style="width:180px">Field</th><th>Value</th><th style="width:70px">Actions</th></tr></thead>' +
            '<tbody>' + rows.join('') + '</tbody></table>';
    }

    _fieldRow(key, value, isMeta) {
        const displayVal = (typeof value === 'object' && value !== null)
            ? JSON.stringify(value) : String(value);
        const escaped = WDash.escapeHtml(displayVal);
        const truncated = displayVal.length > 300 ? escaped.substring(0, 300) + '...' : escaped;

        // The table keys are already the names the query language speaks:
        // neutral fields (severity, body, service, trace_id) for what the model
        // maps, and the original name for resource/attribute entries. The
        // adapter translates them to backend fields, so nothing is needed here.
        const queryKey = key;
        const filterQuery = (typeof value === 'string')
            ? queryKey + ':' + WDash.quoted(value)
            : queryKey + ':' + value;
        const attr = (q) => q.replace(/&/g, '&amp;').replace(/"/g, '&quot;');

        const actions = isMeta ? '' :
            '<span class="field-action" title="Filter for value" data-filter="' + attr(filterQuery) + '">&#128269;</span> ' +
            '<span class="field-action" title="Exclude value" data-exclude="' + attr('NOT ' + filterQuery) + '">&#10134;</span>';

        return '<tr' + (isMeta ? ' class="text-muted"' : '') + '>' +
            '<td><code class="hl-key">' + WDash.escapeHtml(key) + '</code></td>' +
            '<td class="text-break" style="max-width:0;word-break:break-all"><small>' + truncated + '</small></td>' +
            '<td class="text-nowrap">' + actions + '</td></tr>';
    }

    /**
     * Make the magnifier and minus icons in the field table do something.
     *
     * This is the shortest path from "I noticed this value" to "show me
     * everything with it" — the reason to open a record at all is usually to
     * find the next query, not to read that one record.
     *
     * Re-bound every time the table is re-rendered (the full record arrives
     * after the modal opens), so the handlers must be idempotent: a `bound`
     * marker prevents stacking a second listener on a surviving element.
     */
    _bindFieldActions() {
        const self = this;
        document.querySelectorAll('#fieldsView [data-filter], #fieldsView [data-exclude]')
            .forEach(function (el) {
                if (el.dataset.bound === 'true') return;
                el.dataset.bound = 'true';
                el.addEventListener('click', function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                    self._applyFieldFilter(el.dataset.filter || el.dataset.exclude);
                });
            });
    }

    /**
     * Add a clause to the current search and re-run it.
     *
     * Clauses accumulate with AND, which is what narrowing down means: each
     * click should cut the result set, not replace the question. A bare `*`
     * is treated as "no filter yet" rather than a clause to preserve.
     */
    _applyFieldFilter(clause) {
        if (!clause) return;

        const input = document.getElementById('query');
        if (!input) return;

        const current = (input.value || '').trim();
        if (current && current !== '*' && current.indexOf(clause) === -1) {
            // Grouped when it holds an OR: `level:ERROR OR level:WARN` with a
            // clause added was `level:ERROR OR (level:WARN AND …)`, the
            // clause binding to the last term only. The parser takes `or` in
            // any case, and not inside quotes.
            const unquoted = current.replace(/"(?:[^"\\]|\\.)*"/g, '""');
            input.value = (/(^|[\s()])or(?=[\s()]|$)/i.test(unquoted)
                ? '(' + current + ')' : current) + ' AND ' + clause;
        } else if (!current || current === '*') {
            input.value = clause;
        }

        // Close the record: the user is now asking a different question, and
        // leaving the modal over the results hides the answer.
        const modal = document.getElementById('logModal');
        if (modal && window.bootstrap) {
            const instance = bootstrap.Modal.getInstance(modal);
            if (instance) instance.hide();
        }

        this.currentPage = 0;
        this.currentSearchAfter = null;
        this.searchAfterStack = [];
        this.performSearch();
    }

    /**
     * The list view only fetches core fields; the full record is loaded when
     * the modal opens.
     */
    /**
     * The URL of one record's detail, raw or context view.
     *
     * With the record's own `source`, which is what the server now reads it
     * from: these used to ask the default source whatever the record's
     * origin. And the id is everything after the second colon — split
     * without a limit, an id that itself contains a colon was cut short.
     */
    _recordUrl(ref, suffix, params) {
        const parts = (ref || '').split(':');
        const query = new URLSearchParams(params || {});
        const source = this._openRecord && this._openRecord.source;
        if (source) query.set('source', source);
        const qs = query.toString();
        return '/api/log/' + encodeURIComponent(parts[1] || '') + '/' +
               encodeURIComponent(parts.slice(2).join(':')) + (suffix || '') +
               (qs ? '?' + qs : '');
    }

    async _loadFullRecord(ref) {
        if (!ref) return;
        try {
            const response = await fetch(this._recordUrl(ref));
            const data = await response.json();
            if (!data.found || !data.record) return;

            const table = document.querySelector('.field-table-container');
            if (table) {
                table.innerHTML = this._renderFieldTable(data.record);
                this._bindFieldActions();
            }
            const jsonCode = document.querySelector('#jsonView pre code');
            if (jsonCode) {
                jsonCode.innerHTML = WDash.highlightJson(JSON.stringify(data.record, null, 2));
            }
        } catch (e) {
            console.warn('Could not load full record:', e);
        }
    }

    _setupModalTabs(ref) {
        var self = this;
        var tabs = [
            {btn: 'tabFields', view: 'fieldsView'},
            {btn: 'tabMessage', view: 'messageView'},
            {btn: 'tabRawJson', view: 'jsonView'},
            {btn: 'tabSource', view: 'sourceView'}
        ];
        tabs.forEach(function(tab) {
            var el = document.getElementById(tab.btn);
            if (!el) return;
            el.addEventListener('click', function() {
                tabs.forEach(function(t) {
                    var b = document.getElementById(t.btn);
                    var v = document.getElementById(t.view);
                    if (t.btn === tab.btn) {
                        v.classList.remove('d-none');
                        b.classList.replace('btn-outline-secondary', 'btn-outline-primary');
                        b.classList.add('active');
                    } else {
                        v.classList.add('d-none');
                        b.classList.replace('btn-outline-primary', 'btn-outline-secondary');
                        b.classList.remove('active');
                    }
                });
                if (tab.btn === 'tabFields') self._bindFieldActions();
                // Costs an extra request, so it waits until someone asks.
                if (tab.btn === 'tabSource') self._loadRawDocument(ref);
            });
        });
        this._bindFieldActions();
    }

    /**
     * The stored document, in the backend's own shape.
     *
     * `fetch` returns what WDash understood; this returns what actually
     * arrived. When a field is missing from the record view, that difference
     * is the whole question — and the alternative to answering it here is a
     * shell on the Elasticsearch host.
     */
    async _loadRawDocument(ref) {
        const code = document.getElementById('sourceCode');
        if (!code || code.dataset.loaded === 'true') return;
        code.dataset.loaded = 'true';   // set first: no double fetch on re-click

        const fail = (message) => {
            code.classList.add('text-warning');
            code.textContent = message;
            code.dataset.loaded = '';   // let the user retry by switching tabs
        };

        if (!ref) return fail('No record handle, so the stored document cannot be located.');

        try {
            const response = await fetch(this._recordUrl(ref, '/raw'));
            const data = await response.json();
            if (!response.ok || !data.found) {
                return fail(data.error || `Could not load the stored document (HTTP ${response.status}).`);
            }
            code.classList.remove('text-muted', 'text-warning');
            code.innerHTML = WDash.highlightJson(JSON.stringify(data.document, null, 2));
        } catch (e) {
            fail('Could not load the stored document: ' + e.message);
        }
    }

    /**
     * Bound once. The controls live in the modal's footer, which survives
     * between records, and they used to gain a listener on every opening —
     * so one click asked for the context of every record opened so far, and
     * whichever answered last was shown under the current one.
     */
    _setupContextButtons() {
        if (this._contextBound) return;
        this._contextBound = true;
        const current = () => this._openRecord && this._openRecord.ref;
        const mainBtn = document.getElementById('contextAllBtn');
        if (mainBtn) {
            mainBtn.addEventListener('click', () => this._loadContext(current(), ''));
        }
        document.querySelectorAll('.context-option').forEach(el => {
            el.addEventListener('click', (e) => {
                e.preventDefault();
                this._loadContext(current(), el.dataset.field);
            });
        });
    }

    async _loadContext(ref, field) {
        if (!ref) return;

        let box = document.getElementById('contextContainer');
        if (!box) {
            box = document.createElement('div');
            box.id = 'contextContainer';
            box.className = 'mt-3 pt-3 border-top';
            document.getElementById('logModalBody').appendChild(box);
        }
        box.innerHTML = '<div class="text-center py-3"><div class="spinner-border spinner-border-sm text-info"></div> Loading context...</div>';

        try {
            const params = {count: '10'};
            if (field) params.field = field;
            const response = await fetch(this._recordUrl(ref, '/context', params));
            const data = await response.json();
            if (!response.ok) {
                box.innerHTML = '<div class="text-danger"><i class="fas fa-exclamation-circle"></i> ' +
                    WDash.escapeHtml(data.error || 'Failed to load context') + '</div>';
                return;
            }

            const label = data.correlated_by ? 'Same ' + data.correlated_by : 'Time-based';
            let html = '<h6 class="mb-3"><i class="fas fa-stream text-info"></i> Surrounding Logs ' +
                       '<small class="text-muted">(' + WDash.escapeHtml(label) + ')</small></h6>';

            if (!data.before.length && !data.after.length) {
                html += '<p class="text-muted text-center">No surrounding logs found</p>';
            } else {
                html += '<div class="context-logs">';
                data.before.forEach(r => { html += this._renderContextLog(r, false); });
                html += '<div class="context-current-marker"><i class="fas fa-arrow-right text-warning"></i> Current log entry</div>';
                data.after.forEach(r => { html += this._renderContextLog(r, false); });
                html += '</div>';
            }
            box.innerHTML = html;
        } catch (e) {
            box.innerHTML = '<div class="text-danger"><i class="fas fa-exclamation-circle"></i> Network error loading context</div>';
        }
    }

    _renderContextLog(record, isCurrent) {
        const esc = WDash.escapeHtml;
        const severity = record.severity_text || record.severity || 'INFO';
        const message = record.body || '';
        return '<div class="' + (isCurrent ? 'context-log current' : 'context-log') + '">' +
            '<span class="log-level ' + WDash.levelClass(record) +
                '" style="font-size:0.65rem;padding:2px 6px;">' + esc(severity) + '</span> ' +
            '<small class="text-muted">' + esc(WDash.formatTimestamp(record.timestamp)) + '</small> ' +
            '<small class="fw-bold">' + esc(record.service || '') + '</small> ' +
            '<small class="text-break">' + esc(message.substring(0, 150)) +
                (message.length > 150 ? '...' : '') + '</small>' +
            '</div>';
    }


    /**
     * Surface warnings from the search itself.
     *
     * A merged search over several backends can come back with one of them
     * down: the page renders, with fewer rows and no sign that anything is
     * missing. Fewer rows looks exactly like less data, so the warning has to
     * be on the screen rather than in the payload.
     */
    showSearchWarnings(data) {
        const holder = document.getElementById('searchWarnings');
        if (!holder) return;

        const warnings = data.warnings || [];
        if (!warnings.length && !data.partial) {
            holder.innerHTML = '';
            holder.classList.add('d-none');
            return;
        }

        const escape = (value) => String(value).replace(/[&<>]/g,
            c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;'}[c]));
        const tone = data.partial ? 'warning' : 'secondary';
        const icon = data.partial ? 'triangle-exclamation' : 'circle-info';

        holder.classList.remove('d-none');
        holder.innerHTML =
            `<div class="alert alert-${tone} py-2 mb-2" style="font-size:.85rem">` +
            `<i class="fas fa-${icon}"></i> ` +
            (data.partial
                ? '<strong>These results are incomplete.</strong> '
                : '') +
            warnings.map(escape).join('<br>') +
            '</div>';
    }

    updatePagination() {
        const pagination = document.getElementById('pagination');
        const beyond = this.totalResults > (this.currentPage + 1) * this.pageSize;
        // A next page needs a cursor to ask for it with. Without one the
        // request is page one again.
        const hasMore = beyond && Boolean(this.currentSearchAfter);
        // More than fits and no way to page to it: said, rather than a Next
        // that cannot deliver.
        const merged = this.answeredBy > 1;
        const why = merged
            ? 'a search across ' + this.answeredBy + ' sources cannot page '
              + 'further — each backend\'s cursor means something different '
              + 'and advancing them together would skip records'
            : 'this source cannot page further';
        const note = (beyond && !hasMore)
            ? '<small class="text-muted d-block text-center">Showing the first ' +
              ((this.currentPage + 1) * this.pageSize).toLocaleString() + ' of ' +
              this.totalResults.toLocaleString() + '; ' + why +
              ', so narrow the time range to see the rest.</small>'
            : '';
        
        if (!hasMore && this.currentPage === 0) {
            pagination.innerHTML = note;
            return;
        }
        
        let html = '<nav><ul class="pagination pagination-sm justify-content-center">';
        
        // First page button
        if (this.currentPage > 0) {
            html += `<li class="page-item">
                <a class="page-link" href="#" id="paginationFirst">First</a>
            </li>`;
        }
        
        // Current page indicator
        html += `<li class="page-item active">
            <span class="page-link">Page ${this.currentPage + 1}</span>
        </li>`;
        
        // Next page button
        if (hasMore) {
            html += `<li class="page-item">
                <a class="page-link" href="#" id="paginationNext">Next</a>
            </li>`;
        }
        
        html += '</ul></nav>' + note;
        pagination.innerHTML = html;
        
        // Next: use current search_after cursor
        const nextBtn = document.getElementById('paginationNext');
        if (nextBtn) {
            nextBtn.addEventListener('click', (e) => {
                e.preventDefault();
                // Push current cursor to stack before moving forward
                this.searchAfterStack.push(this.currentSearchAfter);
                this.currentPage++;
                this.performSearch();
            });
        }
        
        // First: reset to page 0
        const firstBtn = document.getElementById('paginationFirst');
        if (firstBtn) {
            firstBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.currentPage = 0;
                this.currentSearchAfter = null;
                this.searchAfterStack = [];
                this.performSearch();
            });
        }
    }

    showLoading(show) {
        const spinner = document.getElementById('loadingSpinner');
        if (spinner) {
            spinner.classList.toggle('d-none', !show);
        }
    }
}

// Initialize WDash when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    try {
        console.log('DOM loaded, initializing WDash...');

        window.wdash = new WDash();
        
        // Initialize search if on logs page
        if (document.getElementById('searchForm')) {
            console.log('Initializing log search...');
            window.logSearch = new LogSearch();
        }
        
    } catch (error) {
        console.error('Error initializing WDash:', error);
        // Show error to user
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger';
        errorDiv.innerHTML = '<strong>JavaScript Error:</strong> Failed to initialize WDash. Please check the console for details.';
        document.body.insertBefore(errorDiv, document.body.firstChild);
    }
});

// Additional initialization for post-login scenarios
window.addEventListener('load', function() {
    // Double-check initialization after full page load
    setTimeout(() => {
        if (document.getElementById('searchForm') && (!window.logSearch || !window.logSearch.initialized)) {
            console.log('Re-initializing log search after page load...');
            window.logSearch = new LogSearch();
        }
    }, 200);
});

// Re-initialize on navigation (for SPA-like behavior)
window.addEventListener('popstate', function() {
    setTimeout(() => {
        if (document.getElementById('searchForm') && (!window.logSearch || !window.logSearch.initialized)) {
            console.log('Re-initializing log search after navigation...');
            window.logSearch = new LogSearch();
        }
    }, 200);
});

// Handle visibility change (when user switches tabs and comes back)
document.addEventListener('visibilitychange', function() {
    if (!document.hidden) {
        setTimeout(() => {
            if (document.getElementById('searchForm') && (!window.logSearch || !window.logSearch.initialized)) {
                console.log('Re-initializing log search after visibility change...');
                window.logSearch = new LogSearch();
            }
        }, 100);
    }
});

// Global function to reinitialize WDash components (useful for debugging or post-login issues)
window.reinitializeWDash = function() {
    console.log('Manually reinitializing WDash...');
    
    try {
        // Reinitialize search if on logs page
        if (document.getElementById('searchForm')) {
            if (window.logSearch && typeof window.logSearch.reinitialize === 'function') {
                window.logSearch.reinitialize();
            } else {
                window.logSearch = new LogSearch();
            }
            console.log('LogSearch reinitialized');
        }
        
        console.log('WDash reinitialization complete');
        return true;
    } catch (error) {
        console.error('Error reinitializing WDash:', error);
        return false;
    }
};

// Debug helper function
window.debugWDash = function() {
    console.log('=== WDash Debug Information ===');
    console.log('Search form exists:', !!document.getElementById('searchForm'));
    console.log('Clear button exists:', !!document.getElementById('clearBtn'));
    console.log('LogSearch instance exists:', !!window.logSearch);
    console.log('LogSearch initialized:', window.logSearch ? window.logSearch.initialized : 'N/A');
    
    if (window.logSearch) {
        console.log('LogSearch current page:', window.logSearch.currentPage);
        console.log('LogSearch total results:', window.logSearch.totalResults);
        console.log('LogSearch page size:', window.logSearch.pageSize);
        console.log('Clear button handler exists:', !!window.logSearch.clearButtonHandler);
    }
    
    console.log('=== End Debug Information ===');
    return {
        searchForm: !!document.getElementById('searchForm'),
        clearButton: !!document.getElementById('clearBtn'),
        logSearchExists: !!window.logSearch,
        logSearchInitialized: window.logSearch ? window.logSearch.initialized : false,
        clearHandlerExists: window.logSearch ? !!window.logSearch.clearButtonHandler : false
    };
};
