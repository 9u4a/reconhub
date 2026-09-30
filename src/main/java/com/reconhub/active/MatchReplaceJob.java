package com.reconhub.active;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** One Match & Replace bulk-send run: the fixed target count, progress, cancel state, and results so
 * far. Unlike {@link BruteforceJob}, there's no per-host request budget -- the target set is already
 * fixed (the endpoints the user selected before confirming), not an open-ended wordlist. */
public final class MatchReplaceJob {

    private final int total;
    private final AtomicInteger sent = new AtomicInteger();
    private final List<MatchReplaceResult> results = new CopyOnWriteArrayList<>();
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private volatile boolean done;

    public MatchReplaceJob(int total) {
        this.total = total;
    }

    public void recordResult(MatchReplaceResult r) {
        results.add(r);
        sent.incrementAndGet();
    }

    public int getTotal() { return total; }
    public int getSent() { return sent.get(); }
    public List<MatchReplaceResult> getResults() { return results; }

    public void cancel() { cancelled.set(true); }
    public boolean isCancelled() { return cancelled.get(); }

    public void markDone() { this.done = true; }
    public boolean isDone() { return done; }
}
