/**
 * The CSRF token, on every state-changing fetch this application makes.
 *
 * A file rather than an inline block in `base.html` for two reasons: jsdom
 * can load it, so the behaviour below is tested rather than described; and
 * the Content-Security-Policy has one fewer inline script to carry a nonce
 * for.
 *
 * Loaded before every other script, because a call made during one of their
 * module bodies has to be wrapped too.
 */
(function () {
    // Every state-changing fetch this application makes is same-origin
    // and needs the token. Wrapped once here rather than added at each
    // of the five call sites: a sixth one written next year would
    // otherwise be refused, and the refusal would arrive as "the page
    // stopped working" rather than as "you forgot the header".
    //
    // Cross-origin calls are left alone — the token is ours, and
    // sending it to somebody else's server would be handing it over.
    var meta = document.querySelector('meta[name="csrf-token"]');
    var token = meta ? meta.getAttribute('content') : '';
    var inner = window.fetch;
    if (!token || typeof inner !== 'function') { return; }
    window.fetch = function (resource, options) {
        options = options || {};
        var method = (options.method || 'GET').toUpperCase();
        var url = (typeof resource === 'string'
                   ? resource : (resource && resource.url) || '');
        var elsewhere = /^[a-z]+:\/\//i.test(url)
            && url.indexOf(window.location.origin) !== 0;
        if (method !== 'GET' && method !== 'HEAD' && !elsewhere) {
            var headers = new Headers(options.headers || {});
            if (!headers.has('X-CSRF-Token')) {
                headers.set('X-CSRF-Token', token);
            }
            options = Object.assign({}, options, { headers: headers });
        }
        return inner.call(this, resource, options);
    };
})();
