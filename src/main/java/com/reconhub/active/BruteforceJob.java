package com.reconhub.active;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** One bruteforce run against one host: request budget, progress, cancel state, and the hits found. */
public final class BruteforceJob {

    /** One confirmed hit: the path, its response, and the wordlist tag that classified it. */
    public record Hit(String path, int status, int lengthBytes, String tag) {}

    private final String host;
    private final String baseUrl;
    private final int budget;
    private final AtomicInteger sent = new AtomicInteger();
    private final List<Hit> hits = new CopyOnWriteArrayList<>();
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private volatile boolean done;

    /** @param baseUrl the exact origin probed, e.g. {@code "http://127.0.0.1:8090"} — kept so a hit's
     *                 full URL (host + path) can be reconstructed with the scheme actually used. */
    public BruteforceJob(String host, String baseUrl, int budget) {
        this.host = host;
        this.baseUrl = baseUrl;
        this.budget = budget;
    }

    /** Reserves one request against the budget; false when the budget is spent. */
    public boolean tryReserve() {
        return sent.incrementAndGet() <= budget;
    }

    public void recordHit(Hit hit) {
        hits.add(hit);
    }

    public String getHost() { return host; }
    public String getBaseUrl() { return baseUrl; }
    public int getBudget() { return budget; }
    public int getSent() { return Math.min(sent.get(), budget); }
    public int getHits() { return hits.size(); }
    public List<Hit> getHitList() { return hits; }

    public void cancel() { cancelled.set(true); }
    public boolean isCancelled() { return cancelled.get(); }

    public void markDone() { this.done = true; }
    public boolean isDone() { return done; }
}
