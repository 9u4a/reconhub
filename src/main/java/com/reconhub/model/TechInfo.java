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
    // Sorted, immutable snapshots kept in sync by the mutators below, not rebuilt on every read
    // (0.43.9) -- same rationale as Endpoint's paramNamesSorted/sourcesSorted/originsSorted: these are
    // hit from cell rendering (TechPanel) far more often than they're written.
    private volatile Set<String> technologiesSorted = Set.of();
    private volatile Set<String> missingSecurityHeadersSorted = Set.of();

    public TechInfo(String host) {
        this.host = host;
    }

    public String key() {
        return host;
    }

    public void addTechnology(String tech) {
        if (tech != null && !tech.isBlank() && technologies.add(tech)) {
            technologiesSorted = Collections.unmodifiableSet(new TreeSet<>(technologies));
        }
    }

    /** Replace the missing-header set (recomputed from the latest response of the host). */
    public void setMissingSecurityHeaders(Set<String> missing) {
        missingSecurityHeaders.clear();
        if (missing != null) {
            missingSecurityHeaders.addAll(missing);
        }
        missingSecurityHeadersSorted = Collections.unmodifiableSet(new TreeSet<>(missingSecurityHeaders));
    }

    public String getHost() { return host; }
    public Set<String> getTechnologies() { return technologiesSorted; }
    public Set<String> getMissingSecurityHeaders() { return missingSecurityHeadersSorted; }

    /** @return true when there's at least one missing security header (0.43.9) -- an O(1) check for a
     * caller that would otherwise materialize {@link #getMissingSecurityHeaders()}'s sorted snapshot
     * just to call {@code .isEmpty()} on it. */
    public boolean hasMissingSecurityHeaders() {
        return !missingSecurityHeaders.isEmpty();
    }
}
