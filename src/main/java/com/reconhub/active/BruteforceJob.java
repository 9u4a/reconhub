package com.reconhub.active;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** One bruteforce run against one host: request budget, progress, cancel state, running hit count. */
public final class BruteforceJob {

    private final String host;
    private final int budget;
    private final AtomicInteger sent = new AtomicInteger();
    private final AtomicInteger hits = new AtomicInteger();
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private volatile boolean done;

    public BruteforceJob(String host, int budget) {
        this.host = host;
        this.budget = budget;
    }

    /** Reserves one request against the budget; false when the budget is spent. */
    public boolean tryReserve() {
        return sent.incrementAndGet() <= budget;
    }

    public void recordHit() {
        hits.incrementAndGet();
    }

    public String getHost() { return host; }
    public int getBudget() { return budget; }
    public int getSent() { return Math.min(sent.get(), budget); }
    public int getHits() { return hits.get(); }

    public void cancel() { cancelled.set(true); }
    public boolean isCancelled() { return cancelled.get(); }

    public void markDone() { this.done = true; }
    public boolean isDone() { return done; }
}
