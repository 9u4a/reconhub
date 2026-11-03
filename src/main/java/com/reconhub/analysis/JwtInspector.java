package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.google.gson.JsonObject;
import com.reconhub.core.DataStore;
import com.reconhub.model.Finding;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive JWT weakness findings (0.57.0): decodes tokens seen in captured traffic (Authorization header,
 * cookies, response bodies) and reports alg=none, symmetric HS* signing, a missing / very long expiry,
 * key-lookup headers (kid / jku / x5u / jwk), and sensitive or privilege claims -- each with a Try hint.
 * Never verifies a signature or sends anything.
 *
 * <p>One finding per host + issue: every login mints a new token, so the token itself (kept as the masked
 * rawMatch, decodable in the Findings JWT tab) can't be the dedup key. {@link #emitted} remembers the
 * finding key per host + issue and re-emits only once that finding is gone from the store (host delete /
 * clear).
 */
public final class JwtInspector {

    public static final String TYPE_PREFIX = "JWT weakness: ";
    static final long LONG_LIVED_DAYS = 30;
    private static final int MAX_TOKENS_PER_MESSAGE = 4;
    private static final int MAX_EMITTED = 5_000;
    // Like JwtDecoder's pattern but the signature may be empty (alg=none). Bounded, self-limiting classes.
    static final Pattern TOKEN = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{5,4000}\\.eyJ[A-Za-z0-9_-]{5,16000}\\.[A-Za-z0-9_-]{0,2000}");

    /** One weakness of one token. */
    public record Issue(String label, Finding.Severity severity, String tryHint) {
    }

    private final DataStore store;
    private final PatternRegistry.LeadRules rules;
    private final Map<String, String> emitted = new ConcurrentHashMap<>();

    public JwtInspector(DataStore store, PatternRegistry.LeadRules rules) {
        this.store = store;
        this.rules = rules;
    }

    /** Scans each text (header values, bodies) for tokens and records their issues for {@code host}. */
    public void inspect(String host, String url, List<String> texts, HttpRequestResponse rr) {
        if (texts == null || host == null) {
            return;
        }
        for (String token : tokensIn(texts)) {
            JwtDecoder.Parsed p = JwtDecoder.parse(token);
            if (p == null || p.header() == null) {
                continue;
            }
            for (Issue issue : issues(p, rules, Instant.now().getEpochSecond())) {
                String slot = host.toLowerCase(Locale.ROOT) + "|" + issue.label();
                String prev = emitted.get(slot);
                if (prev != null && store.hasFinding(prev)) {
                    continue;
                }
                Finding f = new Finding(TYPE_PREFIX + issue.label(), issue.severity(), token, url,
                        summary(p) + "  |  Try: " + issue.tryHint(), true);
                f.setMessages(rr);
                store.recordFinding(f);
                if (emitted.size() >= MAX_EMITTED) {
                    emitted.clear();
                }
                emitted.put(slot, f.key());
            }
        }
    }

    static Set<String> tokensIn(List<String> texts) {
        Set<String> out = new LinkedHashSet<>();
        for (String t : texts) {
            if (t == null || t.indexOf("eyJ") < 0) {
                continue;
            }
            Matcher m = TOKEN.matcher(t);
            while (m.find() && out.size() < MAX_TOKENS_PER_MESSAGE) {
                out.add(m.group());
            }
        }
        return out;
    }

    /** Every issue of one decoded token, most severe first. {@code rules} may be null (claim checks skipped). */
    public static List<Issue> issues(JwtDecoder.Parsed p, PatternRegistry.LeadRules rules, long nowEpochSec) {
        List<Issue> out = new ArrayList<>();
        JsonObject h = p.header();
        JsonObject b = p.payload();
        if (h == null) {
            return out;
        }
        String alg = h.has("alg") ? JwtDecoder.str(h, "alg") : "";
        if (alg.equalsIgnoreCase("none")) {
            out.add(new Issue("alg=none", Finding.Severity.HIGH, "the token is unsigned -- edit the claims "
                    + "(sub / role) and resend with an empty signature; the server must reject it"));
        } else if (alg.toUpperCase(Locale.ROOT).startsWith("HS")) {
            out.add(new Issue("symmetric " + alg.toUpperCase(Locale.ROOT), Finding.Severity.LOW,
                    "crack the secret offline (hashcat -m 16500 / jwt_tool -C -d wordlist), then forge claims; "
                            + "also try alg=none and re-signing with an empty secret"));
        }
        if (h.has("kid")) {
            out.add(new Issue("kid header", Finding.Severity.LOW, "kid selects the verification key -- try path "
                    + "traversal (../../../../dev/null with an empty HS256 secret) and SQLi in kid"));
        }
        if (h.has("jku") || h.has("x5u") || h.has("jwk")) {
            out.add(new Issue("embedded key / key URL (jku, x5u, jwk)", Finding.Severity.LOW, "point jku / x5u at "
                    + "a key set you host, or embed your own jwk, and sign with that key (jwt_tool -X s / -X i)"));
        }
        if (b != null) {
            if (!b.has("exp")) {
                out.add(new Issue("no expiry (exp)", Finding.Severity.MEDIUM, "the token never expires -- check "
                        + "whether logout or a password change revokes it, and reuse an old token later"));
            } else {
                long exp = JwtDecoder.asLong(b, "exp");
                long iat = b.has("iat") ? JwtDecoder.asLong(b, "iat") : nowEpochSec;
                if (exp > 0 && iat > 0 && exp > iat && (exp - iat) / 86400 >= LONG_LIVED_DAYS) {
                    out.add(new Issue("long-lived token", Finding.Severity.LOW, "it stays valid for "
                            + ((exp - iat) / 86400) + " days -- check revocation on logout / password change"));
                }
            }
            if (rules != null) {
                List<String> sensitive = new ArrayList<>();
                List<String> privileged = new ArrayList<>();
                for (String k : b.keySet()) {
                    if (PatternRegistry.LeadRules.whole(rules.sensitiveFields, k)) {
                        sensitive.add(k);
                    } else if (PatternRegistry.LeadRules.whole(rules.privilegedFields, k)) {
                        privileged.add(k);
                    }
                }
                if (!sensitive.isEmpty()) {
                    out.add(new Issue("sensitive claim", Finding.Severity.MEDIUM, "the payload is only base64 -- "
                            + String.join(", ", sensitive) + " is readable by anyone holding the token"));
                }
                if (!privileged.isEmpty()) {
                    out.add(new Issue("privilege claim", Finding.Severity.INFO, "change " + String.join(", ",
                            privileged) + " and resend -- it escalates if the signature isn't checked (alg=none, "
                            + "weak HS secret, kid/jku tricks)"));
                }
            }
        }
        return out;
    }

    /** alg + key headers + claim names -- never claim values (they can hold personal data). */
    static String summary(JwtDecoder.Parsed p) {
        StringBuilder sb = new StringBuilder("alg=");
        JsonObject h = p.header();
        sb.append(h.has("alg") ? JwtDecoder.str(h, "alg") : "?");
        for (String k : new String[]{"kid", "jku", "x5u", "jwk"}) {
            if (h.has(k)) {
                sb.append(", ").append(k);
            }
        }
        if (p.payload() != null) {
            List<String> names = new ArrayList<>(p.payload().keySet());
            sb.append("; claims: ").append(String.join(", ", names.subList(0, Math.min(names.size(), 15))))
                    .append(names.size() > 15 ? ", ..." : "");
        }
        return sb.toString();
    }
}
