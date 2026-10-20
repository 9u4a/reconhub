package com.reconhub.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.reconhub.analysis.ApiSpecAnalyzer;
import com.reconhub.analysis.CommentExtractor;
import com.reconhub.analysis.EndpointExtractor;
import com.reconhub.analysis.JsAnalyzer;
import com.reconhub.analysis.JsFlowAnalyzer;
import com.reconhub.analysis.MisconfigInspector;
import com.reconhub.analysis.ParameterExtractor;
import com.reconhub.analysis.PiiScanner;
import com.reconhub.analysis.PatternRegistry;
import com.reconhub.analysis.RequestInspector;
import com.reconhub.analysis.SecretScanner;
import com.reconhub.analysis.SourceMapDetector;
import com.reconhub.analysis.TechFingerprinter;
import com.reconhub.analysis.UserRuleStore;

import burp.api.montoya.http.message.params.ParsedHttpParameter;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Orchestrates ingestion: runs every request/response through the analyzers and writes results to
 * the {@link DataStore}. Handles both a one-shot bulk sweep of the existing site map and live
 * capture of new traffic via {@link HttpHandler}. All processing happens off the EDT.
 */
public final class TrafficIngestor implements HttpHandler {

    private final MontoyaApi api;
    private final DataStore store;
    private final Settings settings;
    private final ScopeFilter scopeFilter;
    /** Counts temp-file persistence failures for rate-limited logging in {@link #persist}. */
    private final AtomicLong tempFileFailures = new AtomicLong();

    private final ParameterExtractor parameterExtractor;
    private final SecretScanner secretScanner;
    private final SecretScanner userScanner;
    private final UserRuleStore userRules;
    private final SecretScanner signatureScanner;
    private final SecretScanner authzScanner;
    private final JsAnalyzer jsAnalyzer;
    private final SourceMapDetector sourceMapDetector;
    private final TechFingerprinter techFingerprinter;
    private final MisconfigInspector misconfigInspector;
    private final CommentExtractor commentExtractor;
    private final ApiSpecAnalyzer apiSpecAnalyzer;
    private final PiiScanner piiScanner;
    private final RequestInspector requestInspector;

    private final ExecutorService executor =
            Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "reconhub-ingest");
                t.setDaemon(true);
                return t;
            });
    // A single pathological request/response (a slow disk write, an unforeseen catastrophic-backtracking
    // regex, a Montoya API edge case -- any of which has bitten this project before, see CLAUDE.md) must
    // never be able to block `executor`'s one thread forever: that thread is shared by the bulk sweep
    // AND live capture AND manual ingest, so one stuck item would silently freeze all three, with no
    // exception and no high CPU to signal it (confirmed as the actual symptom reported: "ingest gets
    // stuck partway through on a large existing site map, CPU stays low, re-clicking Ingest Site Map
    // does nothing" -- bulkRunning never resets because the sweep loop never returns from that one
    // item). Every `process(...)` call now runs through this with a hard timeout; a timeout logs
    // exactly which URL to investigate and moves on, rather than hanging.
    private final TimeoutRunner itemRunner = new TimeoutRunner("reconhub-ingest-item");
    private static final long ITEM_TIMEOUT_SECONDS = 20;
    private final AtomicBoolean bulkRunning = new AtomicBoolean(false);
    private final AtomicBoolean cancelRequested = new AtomicBoolean(false);

    /** Progress callback for the bulk sweep. */
    public interface ProgressListener {
        void update(int done, int total);
    }

    public TrafficIngestor(MontoyaApi api, DataStore store, Settings settings,
                           PatternRegistry patterns) {
        this.api = api;
        this.store = store;
        this.settings = settings;
        this.scopeFilter = new ScopeFilter(api, settings);
        this.parameterExtractor = new ParameterExtractor(store);
        this.secretScanner = new SecretScanner(store, patterns.secretRules(), true);
        this.userRules = new UserRuleStore(api);
        this.userScanner = new SecretScanner(store, userRules.compiledRules(), true);
        this.signatureScanner = new SecretScanner(store, patterns.signatureRules(), false);
        this.authzScanner = new SecretScanner(store, patterns.authzRules(), false);
        this.commentExtractor = new CommentExtractor(store);
        this.sourceMapDetector = new SourceMapDetector(store);
        // JS-only deep-analysis scanner (0.47.0): crypto/authz/sink/config locators, evidence shown
        // (non-sensitive). Runs inside JsAnalyzer so both live capture and manual JS import are covered.
        SecretScanner jsFindingScanner = new SecretScanner(store, patterns.jsFindingRules(), false);
        JsFlowAnalyzer flowAnalyzer = new JsFlowAnalyzer(store, patterns);
        this.jsAnalyzer = new JsAnalyzer(api, store, patterns, secretScanner, jsFindingScanner,
                flowAnalyzer, commentExtractor, sourceMapDetector, settings);
        this.techFingerprinter = new TechFingerprinter(store, patterns);
        this.misconfigInspector = new MisconfigInspector(store, secretScanner);
        this.apiSpecAnalyzer = new ApiSpecAnalyzer(store);
        this.piiScanner = new PiiScanner(store);
        this.requestInspector = new RequestInspector(store);
    }

    // ---- Bulk sweep of the existing site map ----------------------------

    /** Kicks off a background sweep of {@code siteMap().requestResponses()}. Ignored if running. */
    public void ingestSiteMapAsync(Runnable onDone) {
        ingestSiteMapAsync(onDone, null);
    }

    /** As above, reporting progress and honoring {@link #requestCancelBulk()}. */
    public void ingestSiteMapAsync(Runnable onDone, ProgressListener progress) {
        if (!bulkRunning.compareAndSet(false, true)) {
            return;
        }
        cancelRequested.set(false);
        executor.submit(() -> {
            try {
                List<HttpRequestResponse> items = api.siteMap().requestResponses();
                int total = items.size();
                if (progress != null) {
                    progress.update(0, total);
                }
                int i = 0;
                for (HttpRequestResponse rr : items) {
                    if (cancelRequested.get()) {
                        api.logging().logToOutput("ReconHub: ingest cancelled at " + i + "/" + total);
                        break;
                    }
                    runWithTimeout(rr, "sitemap", true);
                    i++;
                    if (progress != null && (i % 25 == 0 || i == total)) {
                        progress.update(i, total);
                    }
                    if (i % 200 == 0) {
                        store.fireChanged();
                    }
                }
                api.logging().logToOutput("ReconHub: swept " + i + "/" + total + " site map items.");
            } finally {
                bulkRunning.set(false);
                store.fireChanged();
                if (onDone != null) {
                    onDone.run();
                }
            }
        });
    }

    public boolean isBulkRunning() {
        return bulkRunning.get();
    }

    /** Requests the running bulk sweep to stop as soon as possible. */
    public void requestCancelBulk() {
        cancelRequested.set(true);
    }

    /** The editable user-defined detection rules (persisted across restarts). */
    public UserRuleStore userRules() {
        return userRules;
    }

    // ---- Live capture (HttpHandler) ------------------------------------

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (settings.isLiveCaptureEnabled()) {
            final HttpRequest request = responseReceived.initiatingRequest();
            final HttpRequestResponse rr =
                    HttpRequestResponse.httpRequestResponse(request, responseReceived);
            executor.submit(() -> {
                runWithTimeout(rr, "proxy", true);
                store.fireChanged();
            });
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    // ---- Manual ingest (context menu) -----------------------------------

    /** Ingests a user-chosen request/response regardless of scope (source = "manual"). */
    public void ingestExternal(HttpRequestResponse rr) {
        executor.submit(() -> {
            runWithTimeout(rr, "manual", false);
            store.fireChanged();
        });
    }

    /**
     * Analyzes a locally-imported JS file's text through the same pipeline as JS seen in traffic
     * (endpoint/secret extraction, optional save-to-disk) — no request is sent. {@code syntheticUrl}
     * is a display/join key (e.g. {@code "import://app.js"}), not a real URL. Content-hash dedup means
     * re-importing a file whose text was already analyzed is a silent no-op — {@code onDone} reports
     * which.
     */
    public void ingestJsFile(String syntheticUrl, String body, Consumer<Boolean> onDone) {
        executor.submit(() -> {
            try {
                boolean isNew = !store.hasJsAsset(HashUtil.sha256(body));
                jsAnalyzer.analyze(syntheticUrl, body, null);
                store.fireChanged();
                if (onDone != null) {
                    onDone.accept(isNew);
                }
            } catch (RuntimeException e) {
                api.logging().logToError("JS import failed for " + syntheticUrl + ": " + e);
                if (onDone != null) {
                    onDone.accept(false);
                }
            }
        });
    }

    // ---- Core processing ------------------------------------------------

    /**
     * Runs {@link #process(HttpRequestResponse, String, boolean)} through {@link #itemRunner} with a
     * hard {@link #ITEM_TIMEOUT_SECONDS} timeout so one pathological item can never block the caller
     * forever (see {@link #itemRunner}'s field comment for why this matters).
     */
    private void runWithTimeout(HttpRequestResponse rr, String source, boolean respectScope) {
        TimeoutRunner.Outcome outcome = itemRunner.run(() -> process(rr, source, respectScope),
                ITEM_TIMEOUT_SECONDS,
                cause -> api.logging().logToError("ingest item failed (source=" + source + "): " + cause));
        if (outcome == TimeoutRunner.Outcome.TIMED_OUT) {
            api.logging().logToError("ReconHub: ingest item exceeded " + ITEM_TIMEOUT_SECONDS
                    + "s, skipped (source=" + source + "): " + safeUrl(rr));
        }
    }

    private static String safeUrl(HttpRequestResponse rr) {
        try {
            return rr != null && rr.request() != null ? rr.request().url() : "(no request)";
        } catch (RuntimeException e) {
            return "(url unavailable: " + e + ")";
        }
    }

    /**
     * Returns a Burp temp-file-backed copy of {@code rr} (bytes read lazily from disk, off the JVM
     * heap) -- see the call site in {@link #process}. Falls back to the original in-heap {@code rr} if
     * the copy fails for any reason, so a failure only loses the memory saving for that one item, never
     * the item itself. The failure log is rate-limited (1st, then every 100th) the same way the other
     * hot-path failure points in this codebase are, since a persistent cause (e.g. a full temp dir)
     * would otherwise fire on every single ingested item.
     */
    private HttpRequestResponse persist(HttpRequestResponse rr) {
        try {
            return rr.copyToTempFile();
        } catch (RuntimeException e) {
            long n = tempFileFailures.getAndIncrement();
            if (n == 0 || n % 100 == 0) {
                api.logging().logToError("ReconHub: could not persist message to temp file "
                        + "(keeping it in memory instead): " + e);
            }
            return rr;
        }
    }

    private void process(HttpRequestResponse rr, String source, boolean respectScope) {
        if (rr == null || rr.request() == null) {
            return;
        }
        HttpRequest request = rr.request();
        HttpResponse response = rr.response();
        String url = request.url();
        if (respectScope && !scopeFilter.inScope(url)) {
            return;
        }

        // Persist the captured request/response to Burp's own temp-file store and keep THAT handle
        // (`stored`) for everything we record below, instead of the live in-heap `rr`. Burp's
        // copyToTempFile() reads the bytes lazily from disk, so the (often large -- JS bundles, HTML)
        // request+response bodies no longer sit pinned on the JVM heap for the life of the session.
        // This is the single biggest lever on the "memory grows over a multi-day engagement" problem:
        // every retained Endpoint/ParameterInfo/Finding/JsAsset used to hold a full in-heap message.
        // One copy per ingested item, shared by every row derived from it. Runs on the ingest executor
        // (background, already bounded by runWithTimeout), never the EDT.
        HttpRequestResponse stored = persist(rr);

        int status = 0;
        String contentType = "";
        if (response != null) {
            status = response.statusCode();
            String ct = response.headerValue("Content-Type");
            contentType = ct == null ? "" : ct;
        }

        // Skip static assets (never JS) before doing any real work -- this check only needs the URL and
        // Content-Type, both already in hand, so bail out here, before extracting endpoint info or
        // decoding the body (0.43.7: these used to run unconditionally, so every image/font/video/etc.
        // in a swept site map was fully decoded into a String -- and had EndpointExtractor parse its
        // request -- just to be thrown away by this same check, a few lines later than it needed to be).
        if (settings.isIgnoreStaticAssets() && isStaticAsset(url, contentType)) {
            return;
        }

        // Parsed once and shared with EndpointExtractor/ParameterExtractor/RequestInspector (0.43.7) --
        // Montoya re-parses query+body+cookie(+JSON) params from scratch on every request.parameters()
        // call, and all three used to call it independently for the same immutable request.
        List<ParsedHttpParameter> params = request.parameters();
        EndpointExtractor.EndpointInfo ep = EndpointExtractor.extract(request, params);
        String responseBody = response != null ? BodyDecoder.decode(response) : "";

        String endpointKey = ep.normalizedUrl();
        com.reconhub.model.Endpoint endpoint = store.recordEndpoint(ep.method(), ep.host(), ep.path(),
                ep.normalizedUrl(), status, contentType, source, ep.paramNames(), stored, Set.of());
        // Track whether this observation carried credentials (Authorization or any Cookie).
        boolean authed = request.headerValue("Authorization") != null
                || request.headerValue("Cookie") != null;
        endpoint.recordAuth(authed);
        store.countRequest(ep.host(), status, contentType);

        parameterExtractor.extract(request, params, endpointKey, ep.path(), responseBody, stored);

        if (response != null) {
            // Computed once and reused below: a JS body is secret-scanned inside jsAnalyzer.analyze()
            // (which also needs the hit count for JsAsset's "Secrets" column, and is the only scan the
            // manual JS-import path gets) -- scanning it here too was scanning every bundle twice with
            // the same scanner instance. userScanner (the user's custom rules) is NOT run by JsAnalyzer,
            // so it still runs for every response including JS.
            boolean isJs = isJavaScript(url, contentType);
            if (settings.isScanResponsesForSecrets()) {
                if (!isJs) {
                    secretScanner.scan(responseBody, url, stored);
                }
                userScanner.scan(responseBody, url, stored);
            }
            techFingerprinter.fingerprint(ep.host(), response, contentType, responseBody);
            // Passive API-surface discovery (OpenAPI/Swagger/GraphQL) from the captured body.
            apiSpecAnalyzer.analyze(url, contentType, responseBody, stored);
            // Passive source-map exposure (a captured .map is a confirmed original-source leak).
            sourceMapDetector.analyze(url, contentType, responseBody, stored);
            if (isJs) {
                jsAnalyzer.analyze(url, responseBody, stored);
            }
            if (settings.isRunPassiveChecks()) {
                signatureScanner.scan(responseBody, url, stored);
                authzScanner.scan(responseBody, url, stored);
                piiScanner.scan(responseBody, url, stored);
                requestInspector.inspect(request, response, params, url, contentType, responseBody, stored);
                misconfigInspector.inspect(ep.host(), request, response, url, stored);
                if (isHtml(contentType)) {
                    commentExtractor.extractHtml(responseBody, url, stored);
                }
            }
        }
    }

    private static boolean isHtml(String contentType) {
        return contentType.toLowerCase(Locale.ROOT).contains("html");
    }

    // 0.43.7: was a String.matches(".*\\.(?:png|jpe?g|...)$") -- String.matches compiles a fresh
    // Pattern on every call (every ingested message), and the leading ".*" forces a full backtracking
    // scan of the path for every attempt. A plain extension lookup is both allocation-free (no Matcher)
    // and doesn't backtrack.
    private static final Set<String> STATIC_EXTENSIONS = Set.of(
            "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "css",
            "woff", "woff2", "ttf", "eot", "otf",
            "mp4", "webm", "mp3", "wav", "avi", "mov", "pdf");

    /** True for images/fonts/stylesheets/media — deliberately excludes JS. */
    private static boolean isStaticAsset(String url, String contentType) {
        String ct = contentType.toLowerCase(Locale.ROOT);
        if (ct.startsWith("image/") || ct.startsWith("font/") || ct.startsWith("audio/")
                || ct.startsWith("video/") || ct.contains("text/css")) {
            return true;
        }
        String u = url.toLowerCase(Locale.ROOT);
        int q = u.indexOf('?');
        String path = q >= 0 ? u.substring(0, q) : u;
        int dot = path.lastIndexOf('.');
        return dot >= 0 && STATIC_EXTENSIONS.contains(path.substring(dot + 1));
    }

    /** True when a URL/Content-Type pair looks like JavaScript. Public so the UI (e.g.
     * {@code MessageViewer}'s Beautify toggle) can use the exact same "is this JS" test the ingest
     * pipeline uses, instead of maintaining a second copy that could drift out of sync. */
    public static boolean isJavaScript(String url, String contentType) {
        String ct = contentType.toLowerCase(Locale.ROOT);
        if (ct.contains("javascript") || ct.contains("ecmascript")) {
            return true;
        }
        String u = url.toLowerCase(Locale.ROOT);
        int q = u.indexOf('?');
        String pathPart = q >= 0 ? u.substring(0, q) : u;
        return pathPart.endsWith(".js") || pathPart.endsWith(".mjs");
    }

    public void shutdown() {
        executor.shutdownNow();
        itemRunner.shutdown();
    }
}
