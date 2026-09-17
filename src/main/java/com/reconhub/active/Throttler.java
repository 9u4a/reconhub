package com.reconhub.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.reconhub.core.Settings;

/**
 * The single choke point for known-path-bruteforce traffic — the only place in ReconHub that ever
 * calls {@code api.http().sendRequest}. Refuses to send unless the master
 * {@link Settings#isBruteforceActiveEnabled()} switch is on, enforces the per-job request budget via
 * {@link BruteforceJob#tryReserve()}, and paces sends to at least
 * {@link Settings#getBruteforceDelayMs()} apart. Every other part of ReconHub stays strictly passive.
 */
public final class Throttler {

    private final MontoyaApi api;
    private final Settings settings;
    private final Object pace = new Object();
    private long lastSendAt;

    public Throttler(MontoyaApi api, Settings settings) {
        this.api = api;
        this.settings = settings;
    }

    /** @return the response, or {@code null} when sending is refused (off / budget spent / cancelled). */
    public HttpRequestResponse send(HttpRequest request, BruteforceJob job) {
        if (!settings.isBruteforceActiveEnabled() || job.isCancelled() || !job.tryReserve()) {
            return null;
        }
        int delay = settings.getBruteforceDelayMs();
        synchronized (pace) {
            long wait = lastSendAt + delay - System.currentTimeMillis();
            if (wait > 0) {
                try {
                    Thread.sleep(wait);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }
            lastSendAt = System.currentTimeMillis();
        }
        try {
            return api.http().sendRequest(request);
        } catch (RuntimeException e) {
            api.logging().logToError("ReconHub bruteforce send failed: " + e);
            return null;
        }
    }
}
