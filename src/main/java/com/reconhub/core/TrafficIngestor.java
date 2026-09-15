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
import com.reconhub.analysis.MisconfigInspector;
import com.reconhub.analysis.ParameterExtractor;
import com.reconhub.analysis.PiiScanner;
import com.reconhub.analysis.PatternRegistry;
import com.reconhub.analysis.SecretScanner;
import com.reconhub.analysis.TechFingerprinter;
import com.reconhub.analysis.UserRuleStore;

import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

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

    private final ParameterExtractor parameterExtractor;
    private final SecretScanner secretScanner;
    private final SecretScanner userScanner;
    private final UserRuleStore userRules;
    private final SecretScanner signatureScanner;
    private final SecretScanner authzScanner;
    private final JsAnalyzer jsAnalyzer;
    private final TechFingerprinter techFingerprinter;
    private final MisconfigInspector misconfigInspector;
    private final CommentExtractor commentExtractor;
    private final ApiSpecAnalyzer apiSpecAnalyzer;
    private final PiiScanner piiScanner;

    private final ExecutorService executor =
            Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "reconhub-ingest");
                t.setDaemon(true);
                return t;
            });
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
        this.jsAnalyzer = new JsAnalyzer(store, patterns, secretScanner, commentExtractor, settings);
        this.techFingerprinter = new TechFingerprinter(store, patterns);
        this.misconfigInspector = new MisconfigInspector(store);
        this.apiSpecAnalyzer = new ApiSpecAnalyzer(store);
        this.piiScanner = new PiiScanner(store);
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
                    try {
                        process(rr, "sitemap");
                    } catch (RuntimeException e) {
                        api.logging().logToError("ingest item failed: " + e);
                    }
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
                try {
                    process(rr, "proxy");
                    store.fireChanged();
                } catch (RuntimeException e) {
                    api.logging().logToError("live ingest failed: " + e);
                }
            });
        }
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    // ---- Manual ingest (context menu) -----------------------------------

    /** Ingests a user-chosen request/response regardless of scope (source = "manual"). */
    public void ingestExternal(HttpRequestResponse rr) {
        executor.submit(() -> {
            try {
                process(rr, "manual", false);
                store.fireChanged();
            } catch (RuntimeException e) {
                api.logging().logToError("manual ingest failed: " + e);
            }
        });
    }

    // ---- Core processing ------------------------------------------------

    private void process(HttpRequestResponse rr, String source) {
        process(rr, source, true);
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

        EndpointExtractor.EndpointInfo ep = EndpointExtractor.extract(request);

        int status = 0;
        String contentType = "";
        String responseBody = "";
        if (response != null) {
            status = response.statusCode();
            String ct = response.headerValue("Content-Type");
            contentType = ct == null ? "" : ct;
            responseBody = response.bodyToString();
        }

        // Skip static assets (never JS) to cut noise, unless the user disabled it.
        if (settings.isIgnoreStaticAssets() && isStaticAsset(url, contentType)) {
            return;
        }

        String endpointKey = ep.normalizedUrl();
        store.recordEndpoint(ep.method(), ep.host(), ep.path(), ep.normalizedUrl(),
                status, contentType, source, ep.paramNames(), rr, java.util.Set.of());
        store.countRequest(ep.host(), status, contentType);

        parameterExtractor.extract(request, endpointKey, ep.path(), responseBody, rr);

        if (response != null) {
            if (settings.isScanResponsesForSecrets()) {
                secretScanner.scan(responseBody, url, rr);
                userScanner.scan(responseBody, url, rr);
            }
            techFingerprinter.fingerprint(ep.host(), response, contentType);
            // Passive API-surface discovery (OpenAPI/Swagger/GraphQL) from the captured body.
            apiSpecAnalyzer.analyze(url, contentType, responseBody, rr);
            if (isJavaScript(url, contentType)) {
                jsAnalyzer.analyze(url, responseBody, rr);
            }
            if (settings.isRunPassiveChecks()) {
                signatureScanner.scan(responseBody, url, rr);
                authzScanner.scan(responseBody, url, rr);
                piiScanner.scan(responseBody, url, rr);
                misconfigInspector.inspect(ep.host(), request, response, url);
                if (isHtml(contentType)) {
                    commentExtractor.extractHtml(responseBody, url, rr);
                }
            }
        }
    }

    private static boolean isHtml(String contentType) {
        return contentType.toLowerCase(Locale.ROOT).contains("html");
    }

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
        return path.matches(".*\\.(?:png|jpe?g|gif|bmp|ico|svg|webp|css|woff2?|ttf|eot|otf|"
                + "mp4|webm|mp3|wav|avi|mov|pdf)$");
    }

    private static boolean isJavaScript(String url, String contentType) {
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
    }
}
