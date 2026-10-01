package com.reconhub.core;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

/**
 * Runs a task with a hard timeout on its own cached thread pool, so one stuck task (slow disk I/O, an
 * unforeseen catastrophic-backtracking regex, any other pathological case) can never block the calling
 * thread forever. Extracted from {@code TrafficIngestor} (0.43.1 -- a real bug: a single pathological
 * item in a large site map could wedge the ingest pipeline's one shared thread forever, with no
 * exception and no high CPU to signal it, so {@code bulkRunning} never reset and re-clicking "Ingest
 * Site Map" silently did nothing) specifically so the timing/concurrency behavior -- the part that
 * actually matters and that a regression would break -- is headlessly testable on its own, decoupled
 * from any Montoya-specific plumbing (URL extraction, logging) that would make it untestable without a
 * live Burp runtime.
 *
 * <p>On a timeout, the stuck task keeps running in the background on its own daemon thread ({@code
 * Future.cancel(true)} is only a best-effort interrupt -- most blocking I/O and regex matching isn't
 * interruption-aware) while the caller moves on. This trades a bounded thread leak for never hanging
 * permanently, which is the right trade for a background sweep over many items.
 */
public final class TimeoutRunner {

    public enum Outcome { COMPLETED, TIMED_OUT, FAILED }

    private final ExecutorService pool;

    public TimeoutRunner(String threadNamePrefix) {
        this.pool = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, threadNamePrefix);
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * @param onFailure called with the cause when {@code task} throws (never called otherwise).
     * @return {@link Outcome#COMPLETED} if {@code task} finished within {@code timeoutSeconds},
     *         {@link Outcome#TIMED_OUT} if not, {@link Outcome#FAILED} if it threw or this thread was
     *         interrupted while waiting.
     */
    public Outcome run(Runnable task, long timeoutSeconds, Consumer<Throwable> onFailure) {
        Future<?> future = pool.submit(task);
        try {
            future.get(timeoutSeconds, TimeUnit.SECONDS);
            return Outcome.COMPLETED;
        } catch (TimeoutException e) {
            future.cancel(true);
            return Outcome.TIMED_OUT;
        } catch (ExecutionException e) {
            onFailure.accept(e.getCause());
            return Outcome.FAILED;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Outcome.FAILED;
        }
    }

    public void shutdown() {
        pool.shutdownNow();
    }
}
