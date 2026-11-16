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
    private final int id;                                  // 0.61.0: run number (#1, #2, ...)
    private final List<MatchReplaceTarget> targets;        // kept for "Re-run"
    private final List<RunIdentity> identities;
    private final long startedAt = System.currentTimeMillis();
    private final AtomicInteger sent = new AtomicInteger();
    private final List<MatchReplaceResult> results = new CopyOnWriteArrayList<>();
    private final AtomicBoolean cancelled = new AtomicBoolean();
    private volatile boolean done;

    public MatchReplaceJob(int total) {
        this(0, List.of(), List.of(), total);
    }

    public MatchReplaceJob(int id, List<MatchReplaceTarget> targets, List<RunIdentity> identities, int total) {
        this.id = id;
        this.targets = List.copyOf(targets);
        this.identities = List.copyOf(identities);
        this.total = total;
    }

    public int getId() { return id; }
    public List<MatchReplaceTarget> getTargets() { return targets; }
    public List<RunIdentity> getIdentities() { return identities; }
    public long getStartedAt() { return startedAt; }

    /** "#3 · 12 targets × 3 sessions". */
    public String label() {
        int t = targets.isEmpty() ? total : targets.size();
        int s = Math.max(1, identities.size());
        return "#" + id + " · " + t + (t == 1 ? " target" : " targets") + " × " + s + (s == 1 ? " session" : " sessions");
    }

    public void recordResult(MatchReplaceResult r) {
        results.add(r);
        sent.incrementAndGet();
    }

    public int getTotal() { return total; }
    public int getSent() { return sent.get(); }
    public List<MatchReplaceResult> getResults() { return results; }

    /** @return how many results this job has recorded so far (0.43.9) -- lets a caller that keeps its
     * own per-job cursor (see {@code ui.MatchReplacePanel}) tell "nothing new" from "N more to absorb"
     * in O(1), without re-scanning {@link #getResults()}. */
    public int resultCount() {
        return results.size();
    }

    /** @return the results recorded at or after {@code index} (0.43.9) -- pairs with {@link
     * #resultCount()} so a caller can absorb only what's new since it last looked, instead of
     * re-comparing its own accumulated view against the whole list every time. {@code index} beyond
     * the current size (a result list that can only grow, so this shouldn't normally happen) yields an
     * empty list rather than throwing. */
    public List<MatchReplaceResult> resultsFrom(int index) {
        int n = results.size();
        if (index >= n) {
            return List.of();
        }
        return results.subList(Math.max(0, index), n);
    }

    public void cancel() { cancelled.set(true); }
    public boolean isCancelled() { return cancelled.get(); }

    public void markDone() { this.done = true; }
    public boolean isDone() { return done; }
}
