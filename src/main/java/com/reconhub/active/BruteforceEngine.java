package com.reconhub.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.reconhub.core.DataStore;
import com.reconhub.core.ScopeFilter;
import com.reconhub.core.Settings;
import com.reconhub.model.Finding;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Known-path bruteforce: for one host, probes {@link KnownPaths} entries (common admin panels, API
 * docs, exposed config/backup files) and records hits. <b>ACTIVE</b> — every run requires the user's
 * explicit per-run confirmation ({@code ui.RunBruteforceAction}, which shows and lets the user edit the
 * target before running) and the target must pass {@link ScopeFilter}; every send goes through
 * {@link Throttler}, the only choke point that talks to the target.
 *
 * <p>Detection: a soft-404 baseline (one random nonexistent path) is fetched first; a probe response
 * matching that baseline's status and body length (within 3%) is treated as a false hit and skipped.
 * A real hit ({@code status} in {200,201,204,301,302,307,401,403}) is recorded via
 * {@link DataStore#recordEndpoint} (source {@code "bruteforce"}) — no separate results grid — and, for
 * {@code exposed}/{@code admin}/{@code api}-tagged paths, also as a {@link Finding} so it surfaces in
 * triage. Every probe (payload path sent + response status/length) is reported to the
 * {@link Listener#onLog} callback so the Bruteforce tab's activity log shows exactly what was sent and
 * what came back.
 */
public final class BruteforceEngine {

    /** UI callback. Methods may be called off the EDT. */
    public interface Listener {
        void onProgress(BruteforceJob job);
        void onDone(BruteforceJob job);
        void onLog(String message);
    }

    private static final Set<Integer> INTERESTING_STATUS =
            Set.of(200, 201, 204, 301, 302, 307, 401, 403);
    private static final double LEN_TOLERANCE = 0.03;

    private final MontoyaApi api;
    private final DataStore store;
    private final Settings settings;
    private final ScopeFilter scopeFilter;
    private final Throttler throttler;
    private volatile List<KnownPaths.Entry> wordlist;

    // Single-threaded dispatcher: host jobs run one full host at a time, in submission order (matches
    // the "one host at a time" workflow — right-click a host, confirm, it runs to completion or is
    // cancelled before the next queued host starts). Settings.getBruteforceConcurrency() instead
    // controls how many *paths within one job* are probed in parallel — see runWordlist().
    private final ExecutorService dispatcher = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "reconhub-bruteforce");
        t.setDaemon(true);
        return t;
    });
    private final List<BruteforceJob> jobs = new CopyOnWriteArrayList<>();
    private volatile Listener listener = new Listener() {
        @Override public void onProgress(BruteforceJob j) {}
        @Override public void onDone(BruteforceJob j) {}
        @Override public void onLog(String m) {}
    };

    public BruteforceEngine(MontoyaApi api, DataStore store, Settings settings, ScopeFilter scopeFilter,
                            List<KnownPaths.Entry> wordlist) {
        this.api = api;
        this.store = store;
        this.settings = settings;
        this.scopeFilter = scopeFilter;
        this.throttler = new Throttler(api, settings);
        this.wordlist = wordlist;
    }

    public void setListener(Listener l) { this.listener = l == null ? this.listener : l; }
    public void setWordlist(List<KnownPaths.Entry> wordlist) { this.wordlist = wordlist; }
    public List<KnownPaths.Entry> getWordlist() { return wordlist; }
    public List<BruteforceJob> jobs() { return jobs; }

    /** Rough request count a run would send (wordlist size + 1 baseline probe), capped by the budget. */
    public int estimateRequests() {
        return Math.min(wordlist.size() + 1, settings.getBruteforceMaxRequestsPerHost());
    }

    /**
     * Starts a run against {@code target}, e.g. {@code "https://example.com"} or
     * {@code "example.com"} (scheme defaults to {@code https} when omitted). Any path/query on
     * {@code target} is dropped — only the origin is probed. Callers (only
     * {@code ui.RunBruteforceAction}) must have already shown the user a confirmation dialog naming
     * this exact target before calling this.
     * @return the job, or {@code null} if refused (target unparsable, or the resulting origin is not
     * in scope).
     */
    public BruteforceJob submit(String target) {
        if (target == null || target.isBlank()) {
            return null;
        }
        String baseUrl = normalizeOrigin(target.trim());
        if (baseUrl == null) {
            return null;
        }
        if (!scopeFilter.inScope(baseUrl)) {
            return null;
        }
        String host = java.net.URI.create(baseUrl).getHost();
        if (host == null || host.isBlank()) {
            return null;
        }
        BruteforceJob job = new BruteforceJob(host, settings.getBruteforceMaxRequestsPerHost());
        jobs.add(job);
        dispatcher.submit(() -> run(job, baseUrl, host));
        return job;
    }

    private void run(BruteforceJob job, String baseUrl, String host) {
        try {
            log("── Bruteforce start: " + baseUrl + " (" + wordlist.size() + " paths, budget "
                    + job.getBudget() + ")");
            String nonce = "/__reconhub_" + ThreadLocalRandom.current().nextInt(100_000, 999_999) + "__";
            HttpRequestResponse base = send(baseUrl + nonce, job);
            int baseStatus = status(base);
            int baseLen = len(base);
            log("  baseline (random nonexistent path) → " + baseStatus + " " + baseLen + "B");
            if (base == null) {
                log("  ⚠ baseline request failed outright (no response) — every path below will also "
                        + "read 0/0B. Usually a wrong scheme (https vs http) or port for this host; "
                        + "edit the target and re-run.");
            }

            runWordlist(job, baseUrl, host, baseStatus, baseLen);
            log("── Bruteforce done: " + baseUrl + " (requests sent: " + job.getSent()
                    + ", hits: " + job.getHits() + ")");
        } catch (RuntimeException e) {
            api.logging().logToError("ReconHub bruteforce job for " + host + " failed: " + e);
            log("  error: " + e);
        } finally {
            job.markDone();
            listener.onDone(job);
        }
    }

    /**
     * Probes the wordlist against one host, using up to {@code settings.getBruteforceConcurrency()}
     * worker threads pulling from a shared cursor — the actual sends still funnel through the single
     * {@link Throttler} pace lock, so raising concurrency overlaps network wait rather than sending
     * faster than {@code delayMs} apart.
     */
    private void runWordlist(BruteforceJob job, String baseUrl, String host, int baseStatus, int baseLen) {
        int par = Math.max(1, settings.getBruteforceConcurrency());
        AtomicInteger cursor = new AtomicInteger();
        Runnable worker = () -> {
            int i;
            while ((i = cursor.getAndIncrement()) < wordlist.size()) {
                if (job.isCancelled()) {
                    log("  cancelled.");
                    return;
                }
                KnownPaths.Entry entry = wordlist.get(i);
                HttpRequestResponse rr = send(baseUrl + entry.path(), job);
                if (rr == null) {
                    log("  aborted (budget spent / cancelled)");
                    return;
                }
                int st = status(rr);
                int ln = len(rr);
                boolean softNotFound = st == baseStatus && similarLength(ln, baseLen);
                boolean hit = !softNotFound && INTERESTING_STATUS.contains(st);
                log("  ⇐ " + entry.path() + "  → " + st + " " + ln + "B" + (hit ? "  [HIT]" : ""));
                if (hit) {
                    job.recordHit();
                    record(host, entry, st, rr);
                }
                listener.onProgress(job);
            }
        };

        if (par == 1) {
            worker.run();
            return;
        }
        ExecutorService pool = Executors.newFixedThreadPool(par, r -> {
            Thread t = new Thread(r, "reconhub-bruteforce-worker");
            t.setDaemon(true);
            return t;
        });
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int n = 0; n < par; n++) {
                futures.add(pool.submit(worker));
            }
            for (Future<?> f : futures) {
                try {
                    f.get();
                } catch (Exception e) {
                    api.logging().logToError("ReconHub bruteforce worker failed: " + e);
                }
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private HttpRequestResponse send(String url, BruteforceJob job) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url);
            return throttler.send(req, job);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private void record(String host, KnownPaths.Entry entry, int status, HttpRequestResponse rr) {
        String normalizedUrl = rr.request().url();
        String contentType = contentType(rr);
        store.recordEndpoint("GET", host, entry.path(), normalizedUrl, status, contentType,
                "bruteforce", Set.of(), rr, Set.of());

        String tag = entry.tag();
        if ("exposed".equals(tag) && status == 200) {
            store.recordFinding(new Finding(
                    "Exposed sensitive path (bruteforce): " + entry.path(), Finding.Severity.HIGH,
                    normalizedUrl, normalizedUrl,
                    "Known-path bruteforce hit, status " + status, false));
        } else if (("admin".equals(tag) || "api".equals(tag))
                && (status == 200 || status == 401 || status == 403)) {
            store.recordFinding(new Finding(
                    "Known path found (bruteforce): " + entry.path(), Finding.Severity.LOW,
                    normalizedUrl, normalizedUrl,
                    "Known-path bruteforce hit, status " + status, false));
        }
        store.fireChanged();
    }

    /** Normalizes a user-entered target into a bare origin {@code "scheme://host[:port]"} (no
     * path/query) — defaults to {@code https} when no scheme is given. Null if unparsable. */
    private static String normalizeOrigin(String target) {
        try {
            String withScheme = target.matches("(?i)^[a-z][a-z0-9+.-]*://.*") ? target : "https://" + target;
            java.net.URI uri = java.net.URI.create(withScheme);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null || host.isBlank()) {
                return null;
            }
            int port = uri.getPort();
            return scheme + "://" + host + (port > 0 ? ":" + port : "");
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static boolean similarLength(int a, int b) {
        int max = Math.max(a, b);
        return max == 0 || Math.abs(a - b) / (double) max <= LEN_TOLERANCE;
    }

    private static int status(HttpRequestResponse rr) {
        return rr != null && rr.response() != null ? rr.response().statusCode() : 0;
    }

    private static int len(HttpRequestResponse rr) {
        return rr != null && rr.response() != null ? rr.response().bodyToString().length() : 0;
    }

    private static String contentType(HttpRequestResponse rr) {
        if (rr == null || rr.response() == null) {
            return "";
        }
        String ct = rr.response().headerValue("Content-Type");
        return ct == null ? "" : ct;
    }

    private void log(String message) {
        if (api != null) {
            api.logging().logToOutput("ReconHub bruteforce: " + message);
        }
        listener.onLog(message);
    }

    public void shutdown() {
        dispatcher.shutdownNow();
    }
}
