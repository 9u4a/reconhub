package com.reconhub.active;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * "Find in captured traffic" (0.60.0): groups already-captured requests into account candidates -- one per
 * host and distinct set of confirmed credential values (auth headers + session cookies). Pure; the caller
 * turns Montoya requests into {@link Sample}s off the EDT. Reads captured data only; sends nothing.
 */
public final class SessionDiscovery {

    /** Requests considered per run (most recent first) -- bounds the scan on huge sessions. */
    public static final int MAX_SAMPLES = 5_000;

    /** One captured request: host, path, header list ({name, value}), when it was seen. */
    public record Sample(String host, String path, List<String[]> headers, long seenAt) {}

    /** One account candidate. {@code registeredAs} = name of a saved identity with the same values, or "". */
    public record Candidate(String host, Map<String, String> headers, Map<String, String> cookies, int requests,
                            long lastSeen, String samplePath, AuthDetector.TokenInfo token, String registeredAs) {
        public String summary() {
            List<String> names = new ArrayList<>(headers.keySet());
            names.addAll(cookies.keySet());
            return String.join(", ", names);
        }
    }

    private SessionDiscovery() {}

    public static List<Candidate> discover(List<Sample> samples, List<SessionProfiles.Identity> saved) {
        List<Sample> recent = new ArrayList<>(samples);
        recent.sort(Comparator.comparingLong(Sample::seenAt).reversed());
        if (recent.size() > MAX_SAMPLES) recent = recent.subList(0, MAX_SAMPLES);

        Map<String, Builder> groups = new LinkedHashMap<>();
        for (Sample s : recent) {
            Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            Map<String, String> cookies = new TreeMap<>();
            for (AuthDetector.Part p : AuthDetector.detect(s.headers())) {
                if (p.confidence() != AuthDetector.Confidence.CONFIRMED) continue;
                if (p.kind() == AuthDetector.Kind.HEADER) headers.put(p.name(), p.value());
                else cookies.put(p.name(), p.value());
            }
            // CSRF tokens rotate per request/page: keep them (latest value) but never group on them.
            Map<String, String> keyHeaders = withoutCsrf(headers);
            Map<String, String> keyCookies = withoutCsrf(cookies);
            if (keyHeaders.isEmpty() && keyCookies.isEmpty()) continue;
            String key = (s.host() == null ? "" : s.host()) + "\n" + keyHeaders + "\n" + keyCookies;
            Builder b = groups.computeIfAbsent(key, k -> new Builder(s.host(), headers, cookies));
            b.requests++;
            if (s.seenAt() >= b.lastSeen) {
                b.lastSeen = s.seenAt();
                b.samplePath = s.path();
            }
        }
        List<Candidate> out = new ArrayList<>();
        for (Builder b : groups.values()) {
            Map<String, String> h = new LinkedHashMap<>(b.headers);
            Map<String, String> c = new LinkedHashMap<>(b.cookies);
            String registered = "";
            for (SessionProfiles.Identity id : saved) {
                if (sameValues(id, h, c)) {
                    registered = id.name();
                    break;
                }
            }
            List<String> values = new ArrayList<>(h.values());
            values.addAll(c.values());
            out.add(new Candidate(b.host, h, c, b.requests, b.lastSeen, b.samplePath == null ? "" : b.samplePath,
                    AuthDetector.tokenInfo(values), registered));
        }
        out.sort(Comparator.comparing(Candidate::host, Comparator.nullsFirst(Comparator.naturalOrder()))
                .thenComparing(Comparator.comparingLong(Candidate::lastSeen).reversed()));
        return out;
    }

    static boolean isCsrf(String name) {
        String n = name.toLowerCase(java.util.Locale.ROOT);
        return n.contains("csrf") || n.contains("xsrf");
    }

    private static Map<String, String> withoutCsrf(Map<String, String> m) {
        Map<String, String> out = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Map.Entry<String, String> e : m.entrySet()) {
            if (!isCsrf(e.getKey())) out.put(e.getKey(), e.getValue());
        }
        return out;
    }

    /** Same credential values regardless of header-name case (CSRF tokens ignored). */
    private static boolean sameValues(SessionProfiles.Identity id, Map<String, String> h, Map<String, String> c) {
        return withoutCsrf(id.headers()).equals(withoutCsrf(h)) && withoutCsrf(id.cookies()).equals(withoutCsrf(c));
    }

    private static final class Builder {
        final String host;
        final Map<String, String> headers;
        final Map<String, String> cookies;
        int requests;
        long lastSeen = Long.MIN_VALUE;
        String samplePath;

        Builder(String host, Map<String, String> headers, Map<String, String> cookies) {
            this.host = host;
            this.headers = headers;
            this.cookies = cookies;
        }
    }
}
