package com.reconhub.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.reconhub.core.ScopeFilter;
import com.reconhub.core.Settings;
import com.reconhub.model.Endpoint;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Bulk "replay N selected endpoints with a match/replace rule applied" -- 0.42.0's Match & Replace
 * feature. <b>ACTIVE</b> -- unlike known-path bruteforce, this follows the workspace target-load-safety
 * policy's actual default: {@link Settings#isMatchReplaceEnabled()} must be explicitly turned on (off
 * by default), every send is paced by {@link Settings#getMatchReplaceDelayMs()} (this class's own
 * choke point -- the only place here that calls {@code api.http().sendRequest}), and {@code
 * ui.MatchReplaceDialog} requires the user's per-run confirmation before {@link #submit} is ever
 * called, naming exactly how many endpoints and what rule. See {@code Settings}'s field comment for why
 * this doesn't reuse bruteforce's "no master toggle" exception.
 *
 * <p>Unlike {@code active.BruteforceEngine}, the target set here is fixed up front (the endpoints the
 * user selected), not an open-ended wordlist against one host -- so there's no per-host request budget,
 * and {@link MatchReplaceJob} is correspondingly simpler than {@link BruteforceJob}.
 */
public final class MatchReplaceEngine {

    /** UI callback. Methods may be called off the EDT. */
    public interface Listener {
        void onProgress(MatchReplaceJob job);
        void onDone(MatchReplaceJob job);
    }

    private final MontoyaApi api;
    private final Settings settings;
    private final ScopeFilter scopeFilter;

    // Same pacing algorithm as active.Throttler (shared lock + lastSendAt timestamp), but not reusing
    // that class directly -- Throttler.send is written against BruteforceJob specifically
    // (job.tryReserve()/isCancelled()), and forcing this feature's fixed-target-set job shape through
    // it isn't worth risking the already-shipped bruteforce path. Deliberate small duplication.
    private final Object pace = new Object();
    private long lastSendAt;

    // Single-threaded dispatcher, same shape as BruteforceEngine's: one Match & Replace run executes
    // fully (or is cancelled) before the next submitted one starts. settings.getMatchReplaceConcurrency()
    // instead controls how many *targets within one job* are sent in parallel -- see run().
    private final ExecutorService dispatcher = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "reconhub-matchreplace");
        t.setDaemon(true);
        return t;
    });
    private final List<MatchReplaceJob> jobs = new CopyOnWriteArrayList<>();
    private volatile Listener listener = new Listener() {
        @Override public void onProgress(MatchReplaceJob j) {}
        @Override public void onDone(MatchReplaceJob j) {}
    };

    public MatchReplaceEngine(MontoyaApi api, Settings settings, ScopeFilter scopeFilter) {
        this.api = api;
        this.settings = settings;
        this.scopeFilter = scopeFilter;
    }

    public void setListener(Listener l) { this.listener = l == null ? this.listener : l; }
    public List<MatchReplaceJob> jobs() { return jobs; }

    /**
     * Starts a run against {@code targets} with {@code rule} applied to each. Refuses (returns {@code
     * null}) if the feature is disabled in Settings, or there's nothing to send -- callers (only {@code
     * ui.MatchReplaceDialog}) must have already shown the user a confirmation dialog naming exactly how
     * many endpoints and what rule before calling this.
     */
    public MatchReplaceJob submit(List<Endpoint> targets, MatchReplaceRule rule) {
        if (!settings.isMatchReplaceEnabled() || targets == null || targets.isEmpty() || rule == null) {
            return null;
        }
        List<Endpoint> snapshot = new ArrayList<>(targets);
        MatchReplaceJob job = new MatchReplaceJob(snapshot.size());
        jobs.add(job);
        dispatcher.submit(() -> run(job, snapshot, rule));
        return job;
    }

    private void run(MatchReplaceJob job, List<Endpoint> targets, MatchReplaceRule rule) {
        try {
            int par = Math.max(1, settings.getMatchReplaceConcurrency());
            AtomicInteger cursor = new AtomicInteger();
            Runnable worker = () -> {
                int i;
                while ((i = cursor.getAndIncrement()) < targets.size()) {
                    if (job.isCancelled()) {
                        return;
                    }
                    processOne(job, targets.get(i), rule);
                    listener.onProgress(job);
                }
            };
            if (par == 1) {
                worker.run();
            } else {
                runParallel(par, worker);
            }
        } finally {
            job.markDone();
            listener.onDone(job);
        }
    }

    private void runParallel(int par, Runnable worker) {
        ExecutorService pool = Executors.newFixedThreadPool(par, r -> {
            Thread t = new Thread(r, "reconhub-matchreplace-worker");
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
                    api.logging().logToError("ReconHub match&replace worker failed: " + e);
                }
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private void processOne(MatchReplaceJob job, Endpoint target, MatchReplaceRule rule) {
        HttpRequestResponse original = target.getMessages();
        HttpRequest baseReq = original == null ? null : original.request();
        if (baseReq == null) {
            job.recordResult(MatchReplaceResult.failed(target.getHost(), target.getPath(),
                    target.getMethod(), "no captured request to replay"));
            return;
        }
        String url = target.getNormalizedUrl();
        if (url == null || !scopeFilter.inScope(url)) {
            job.recordResult(MatchReplaceResult.failed(target.getHost(), target.getPath(),
                    target.getMethod(), "out of scope"));
            return;
        }
        HttpRequest modified = buildRequest(baseReq, rule);
        if (modified == null) {
            job.recordResult(MatchReplaceResult.failed(target.getHost(), target.getPath(),
                    target.getMethod(), rule.mode() == MatchReplaceRule.Mode.HEADER
                            ? "header \"" + rule.headerName() + "\" not present"
                            : "could not build request"));
            return;
        }
        pace();
        try {
            HttpRequestResponse rr = api.http().sendRequest(modified);
            job.recordResult(MatchReplaceResult.sent(target.getHost(), target.getPath(),
                    target.getMethod(), rr));
        } catch (RuntimeException e) {
            api.logging().logToError("ReconHub match&replace: send failed for " + url + ": " + e);
            job.recordResult(MatchReplaceResult.failed(target.getHost(), target.getPath(),
                    target.getMethod(), "send failed: " + e));
        }
    }

    /**
     * Builds the modified request per {@code rule} -- the one piece of this class that can't be
     * headlessly exercised: a real captured {@code HttpRequest} normally only exists in a live Burp
     * runtime, and RAW mode's {@code HttpRequest.httpRequest(HttpService, String)} is a Montoya static
     * factory, which throws outside one (confirmed for this exact class of call in the 0.36.0 CLAUDE.md
     * note). {@code null} means the rule doesn't apply to this request (HEADER mode, header absent,
     * add-if-missing off) -- distinguished from "built fine" so the caller can record why, not just
     * that it didn't send.
     */
    private static HttpRequest buildRequest(HttpRequest original, MatchReplaceRule rule) {
        if (rule.mode() == MatchReplaceRule.Mode.HEADER) {
            String name = rule.headerName();
            boolean has = original.hasHeader(name);
            String current = has ? original.headerValue(name) : null;
            String next = rule.computeHeaderValue(current);
            if (next == null) {
                return null;
            }
            return has ? original.withUpdatedHeader(name, next) : original.withAddedHeader(name, next);
        }
        String newText = rule.computeRawText(original.toString());
        HttpService service = original.httpService();
        return HttpRequest.httpRequest(service, newText);
    }

    private void pace() {
        int delay = settings.getMatchReplaceDelayMs();
        synchronized (pace) {
            long wait = lastSendAt + delay - System.currentTimeMillis();
            if (wait > 0) {
                try {
                    Thread.sleep(wait);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            lastSendAt = System.currentTimeMillis();
        }
    }

    public void shutdown() {
        dispatcher.shutdownNow();
    }
}
