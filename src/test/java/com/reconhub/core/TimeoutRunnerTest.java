package com.reconhub.core;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code TimeoutRunner} -- the fix for 0.43.1's "ingest hangs forever on one pathological item" bug
 * (see its class javadoc). The timing/concurrency behavior is exactly what a regression here would
 * break, and is fully exercisable with plain {@code Runnable}s -- no Montoya types needed, unlike
 * {@code TrafficIngestor} itself. */
class TimeoutRunnerTest {

    private TimeoutRunner runner;

    @AfterEach
    void tearDown() {
        if (runner != null) {
            runner.shutdown();
        }
    }

    @Test
    void fastTaskCompletesNormally() {
        runner = new TimeoutRunner("test");
        AtomicReference<Throwable> failure = new AtomicReference<>();
        TimeoutRunner.Outcome outcome = runner.run(() -> {}, 5, failure::set);
        assertEquals(TimeoutRunner.Outcome.COMPLETED, outcome);
        assertNull(failure.get());
    }

    @Test
    void slowTaskTimesOutInsteadOfBlockingForever() throws InterruptedException {
        runner = new TimeoutRunner("test");
        CountDownLatch taskStarted = new CountDownLatch(1);
        AtomicReference<Throwable> failure = new AtomicReference<>();

        long start = System.currentTimeMillis();
        TimeoutRunner.Outcome outcome = runner.run(() -> {
            taskStarted.countDown();
            try {
                Thread.sleep(60_000);   // "hangs forever" stand-in -- the whole point is the caller
                                       // must not wait anywhere near this long
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, 1, failure::set);
        long elapsed = System.currentTimeMillis() - start;

        assertTrue(taskStarted.await(2, java.util.concurrent.TimeUnit.SECONDS), "task should have started");
        assertEquals(TimeoutRunner.Outcome.TIMED_OUT, outcome);
        assertTrue(elapsed < 5000, "run() returned after " + elapsed + "ms -- should bail out near the "
                + "1s timeout, not wait anywhere near the task's 60s sleep");
        assertNull(failure.get());   // onFailure is for thrown exceptions, not timeouts
    }

    @Test
    void throwingTaskReportsFailureWithTheOriginalCause() {
        runner = new TimeoutRunner("test");
        AtomicReference<Throwable> failure = new AtomicReference<>();
        RuntimeException boom = new RuntimeException("boom");

        TimeoutRunner.Outcome outcome = runner.run(() -> { throw boom; }, 5, failure::set);

        assertEquals(TimeoutRunner.Outcome.FAILED, outcome);
        assertEquals(boom, failure.get());
    }

    @Test
    void multipleTasksRunIndependently() {
        // A slow (eventually-timing-out) task must not block a later, independent call from
        // completing promptly -- each run() call gets its own worker thread from the pool.
        runner = new TimeoutRunner("test");
        AtomicReference<Throwable> failure = new AtomicReference<>();

        runner.run(() -> {
            try {
                Thread.sleep(60_000);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, 1, failure::set);   // times out after ~1s, leaves its thread sleeping in the background

        long start = System.currentTimeMillis();
        TimeoutRunner.Outcome outcome = runner.run(() -> {}, 5, failure::set);
        long elapsed = System.currentTimeMillis() - start;

        assertEquals(TimeoutRunner.Outcome.COMPLETED, outcome);
        assertTrue(elapsed < 2000, "a fresh fast task took " + elapsed
                + "ms -- must not be stuck behind the previous timed-out task");
    }
}
