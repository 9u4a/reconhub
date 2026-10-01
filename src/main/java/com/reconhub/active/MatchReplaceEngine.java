package com.reconhub.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.reconhub.core.ScopeFilter;
import com.reconhub.core.Settings;

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
 * <p>Unlike {@code active.BruteforceEngine}, the target set here is fixed up front (the rows the user
 * selected), not an open-ended wordlist against one host -- so there's no per-host request budget, and
 * {@link MatchReplaceJob} is correspondingly simpler than {@link BruteforceJob}. Targets come from any
 * of four source tabs (0.43.0) via {@link MatchReplaceTarget}, so this class has no dependency on any
 * one model type.
 *
 * <p>{@code rule} is a <b>list</b> (0.43.0, chaining) -- applied in order, each rule's output feeding
 * the next. Montoya's {@code HttpRequest} is immutable, so this composes naturally: {@link
 * #buildRequest} is a plain left-fold over the list.
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
     * Starts a run against {@code targets} with {@code rules} applied to each, in order. Refuses
     * (returns {@code null}) if the feature is disabled in Settings, or there's nothing to send/apply --
     * callers (only {@code ui.MatchReplaceDialog}) must have already shown the user a confirmation
     * dialog naming exactly how many rows and what rule(s) before calling this.
     */
    public MatchReplaceJob submit(List<MatchReplaceTarget> targets, List<MatchReplaceRule> rules) {
        if (!settings.isMatchReplaceEnabled() || targets == null || targets.isEmpty()
                || rules == null || rules.isEmpty()) {
            return null;
        }
        List<MatchReplaceTarget> snapshot = new ArrayList<>(targets);
        List<MatchReplaceRule> ruleSnapshot = new ArrayList<>(rules);
        MatchReplaceJob job = new MatchReplaceJob(snapshot.size());
        jobs.add(job);
        dispatcher.submit(() -> run(job, snapshot, ruleSnapshot));
        return job;
    }

    private void run(MatchReplaceJob job, List<MatchReplaceTarget> targets, List<MatchReplaceRule> rules) {
        try {
            int par = Math.max(1, settings.getMatchReplaceConcurrency());
            AtomicInteger cursor = new AtomicInteger();
            Runnable worker = () -> {
                int i;
                while ((i = cursor.getAndIncrement()) < targets.size()) {
                    if (job.isCancelled()) {
                        return;
                    }
                    processOne(job, targets.get(i), rules);
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

    private void processOne(MatchReplaceJob job, MatchReplaceTarget target, List<MatchReplaceRule> rules) {
        HttpRequestResponse original = target.messages();
        HttpRequest baseReq = original == null ? null : original.request();
        if (baseReq == null) {
            job.recordResult(MatchReplaceResult.failed(target.host(), target.path(),
                    target.method(), "no captured request to replay"));
            return;
        }
        if (!scopeFilter.inScope(baseReq.url())) {
            job.recordResult(MatchReplaceResult.failed(target.host(), target.path(),
                    target.method(), "out of scope"));
            return;
        }
        HttpRequest modified = buildRequest(baseReq, rules);
        if (modified == null) {
            job.recordResult(MatchReplaceResult.failed(target.host(), target.path(),
                    target.method(), "a rule in the chain didn't apply (header not present, or "
                            + "\"add if missing\" off)"));
            return;
        }
        pace();
        try {
            HttpRequestResponse rr = api.http().sendRequest(modified);
            job.recordResult(MatchReplaceResult.sent(target.host(), target.path(), target.method(), rr));
        } catch (RuntimeException e) {
            api.logging().logToError("ReconHub match&replace: send failed for " + baseReq.url() + ": " + e);
            job.recordResult(MatchReplaceResult.failed(target.host(), target.path(),
                    target.method(), "send failed: " + e));
        }
    }

    /**
     * Builds the modified request by applying every rule in {@code rules} in order -- a plain left-fold,
     * safe because Montoya's {@code HttpRequest} is immutable (each rule's output is the next rule's
     * input). The one piece of this class that can't be headlessly exercised: a real captured {@code
     * HttpRequest} normally only exists in a live Burp runtime, and RAW mode's {@code HttpRequest
     * .httpRequest(HttpService, String)} is a Montoya static factory, which throws outside one
     * (confirmed for this exact class of call in the 0.36.0 CLAUDE.md note). {@code null} means some
     * rule in the chain didn't apply (HEADER mode, header absent, add-if-missing off) -- the whole chain
     * is abandoned at that point rather than skipping just that one rule, so the result is either "every
     * rule applied" or a clear failure, never a silent partial application.
     *
     * <p>{@code public} specifically so {@code ui.MatchReplaceDialog}'s live preview can call the exact
     * same code path that actually sends -- a hand-duplicated copy in the dialog could silently drift
     * from real send behavior, which would be a bad kind of surprise for a security tool.
     */
    public static HttpRequest buildRequest(HttpRequest original, List<MatchReplaceRule> rules) {
        HttpRequest current = original;
        for (MatchReplaceRule rule : rules) {
            current = applyOne(current, rule);
            if (current == null) {
                return null;
            }
        }
        return current;
    }

    private static HttpRequest applyOne(HttpRequest original, MatchReplaceRule rule) {
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
