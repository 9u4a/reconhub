package com.reconhub.active;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Saved identities for Match & Replace's session presets (0.57.0) -- e.g. "user B" = B's Cookie and/or
 * Authorization header values, replayed over a selection captured as user A to test authorization.
 * <b>Memory only, on purpose</b>: these are live session tokens of the engagement, so they are never
 * written to extension preferences, State exports or reports; they are gone when the extension unloads.
 */
public final class SessionProfiles {

    /** Either value may be blank (that header is then removed when the profile is applied). */
    public record Profile(String name, String cookie, String authorization) {
    }

    private final Map<String, Profile> byName = new LinkedHashMap<>();

    /** Adds or replaces (same name) a profile; a blank name is ignored. */
    public synchronized void put(Profile p) {
        if (p == null || p.name() == null || p.name().isBlank()) {
            return;
        }
        byName.put(p.name().trim(), new Profile(p.name().trim(), blankToEmpty(p.cookie()),
                blankToEmpty(p.authorization())));
    }

    public synchronized List<Profile> list() {
        return new ArrayList<>(byName.values());
    }

    public synchronized Profile get(String name) {
        return name == null ? null : byName.get(name);
    }

    /**
     * The rule chain that makes a request carry exactly this identity: each header the profile has is
     * replaced (added if missing), each header it lacks is removed -- so a request captured with both a
     * cookie and a bearer token can't keep the original user's half.
     */
    public static List<MatchReplaceRule> rulesFor(Profile p) {
        List<MatchReplaceRule> out = new ArrayList<>();
        out.add(headerRule("Cookie", p.cookie()));
        out.add(headerRule("Authorization", p.authorization()));
        return out;
    }

    /** Strip every credential the request carries (the "no session" identity). */
    public static List<MatchReplaceRule> removeAuthRules() {
        List<MatchReplaceRule> out = new ArrayList<>();
        out.add(new MatchReplaceRule(MatchReplaceRule.Mode.REMOVE_HEADER, "Cookie", "", false, "", false));
        out.add(new MatchReplaceRule(MatchReplaceRule.Mode.REMOVE_HEADER, "Authorization", "", false, "", false));
        return out;
    }

    private static MatchReplaceRule headerRule(String header, String value) {
        if (value == null || value.isBlank()) {
            return new MatchReplaceRule(MatchReplaceRule.Mode.REMOVE_HEADER, header, "", false, "", false);
        }
        return new MatchReplaceRule(MatchReplaceRule.Mode.HEADER, header, "", false, value.trim(), true);
    }

    private static String blankToEmpty(String s) {
        return s == null ? "" : s.trim();
    }
}
