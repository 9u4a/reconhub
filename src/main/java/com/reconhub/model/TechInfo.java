package com.reconhub.model;

import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-host technology fingerprint + missing security-header checklist.
 * Dedup key = host.
 */
public final class TechInfo {

    private final String host;
    private final Set<String> technologies = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final Set<String> missingSecurityHeaders = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public TechInfo(String host) {
        this.host = host;
    }

    public String key() {
        return host;
    }

    public void addTechnology(String tech) {
        if (tech != null && !tech.isBlank()) {
            technologies.add(tech);
        }
    }

    /** Replace the missing-header set (recomputed from the latest response of the host). */
    public void setMissingSecurityHeaders(Set<String> missing) {
        missingSecurityHeaders.clear();
        if (missing != null) {
            missingSecurityHeaders.addAll(missing);
        }
    }

    public String getHost() { return host; }
    public Set<String> getTechnologies() { return new TreeSet<>(technologies); }
    public Set<String> getMissingSecurityHeaders() { return new TreeSet<>(missingSecurityHeaders); }
}
