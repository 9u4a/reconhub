package com.reconhub.active;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Saved identities for Match &amp; Replace (0.57.0; generalized 0.60.0) -- e.g. "user B" = B's auth headers
 * and session cookies, replayed over a selection captured as user A to test authorization.
 * <b>Memory only, on purpose</b>: these are live session tokens of the engagement, so they are never
 * written to extension preferences, State exports or reports; they are gone when the extension unloads.
 */
public final class SessionProfiles {

    /** Built-in pseudo identity: the request exactly as captured (the comparison baseline). */
    public static final String ORIGINAL = "Original";
    /** Built-in pseudo identity: every credential stripped. */
    public static final String NO_AUTH = "No auth";

    /**
     * A saved identity: auth headers (name → value) and session cookies (name → value). Applying it sets
     * these and strips every other confirmed auth header / session cookie the request carries; other
     * cookies (analytics, locale) stay as captured.
     */
    public record Identity(String name, Map<String, String> headers, Map<String, String> cookies, String source,
                           long capturedAt) {
        public Identity {
            name = name == null ? "" : name.trim();
            headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers == null ? Map.of() : headers));
            cookies = Collections.unmodifiableMap(new LinkedHashMap<>(cookies == null ? Map.of() : cookies));
            source = source == null ? "" : source;
        }

        /** "Authorization, JSESSIONID" -- the part names, headers first. */
        public String summary() {
            List<String> names = new ArrayList<>(headers.keySet());
            names.addAll(cookies.keySet());
            return names.isEmpty() ? "(no credentials)" : String.join(", ", names);
        }

        public AuthDetector.TokenInfo tokenInfo() {
            List<String> values = new ArrayList<>(headers.values());
            values.addAll(cookies.values());
            return AuthDetector.tokenInfo(values);
        }

        /** True when another identity carries exactly the same credential values. */
        public boolean sameCredentials(Map<String, String> otherHeaders, Map<String, String> otherCookies) {
            return headers.equals(otherHeaders) && cookies.equals(otherCookies);
        }
    }

    private final Map<String, Identity> byName = new LinkedHashMap<>();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    /** Adds or replaces (same name) an identity; a blank or built-in name is ignored. */
    public void put(Identity id) {
        if (id == null || id.name().isEmpty() || isBuiltIn(id.name())) {
            return;
        }
        synchronized (this) {
            byName.put(id.name(), id);
        }
        fire();
    }

    public void remove(String name) {
        boolean removed;
        synchronized (this) {
            removed = name != null && byName.remove(name) != null;
        }
        if (removed) fire();
    }

    /** Renames an identity (keeps its position); false when the new name is taken or invalid. */
    public boolean rename(String from, String to) {
        String t = to == null ? "" : to.trim();
        synchronized (this) {
            Identity id = byName.get(from);
            if (id == null || t.isEmpty() || isBuiltIn(t) || (byName.containsKey(t) && !t.equals(from))) return false;
            Map<String, Identity> copy = new LinkedHashMap<>();
            for (Map.Entry<String, Identity> e : byName.entrySet()) {
                if (e.getKey().equals(from)) {
                    copy.put(t, new Identity(t, id.headers(), id.cookies(), id.source(), id.capturedAt()));
                } else {
                    copy.put(e.getKey(), e.getValue());
                }
            }
            byName.clear();
            byName.putAll(copy);
        }
        fire();
        return true;
    }

    /** Saved identities (built-ins excluded), in insertion order. */
    public synchronized List<Identity> list() {
        return new ArrayList<>(byName.values());
    }

    public synchronized Identity get(String name) {
        return name == null ? null : byName.get(name);
    }

    /** A name not yet used: base, base 2, base 3, ... */
    public synchronized String uniqueName(String base) {
        String b = base == null || base.isBlank() ? "user" : base.trim();
        if (!byName.containsKey(b) && !isBuiltIn(b)) return b;
        for (int i = 2; ; i++) {
            String n = b + " " + i;
            if (!byName.containsKey(n)) return n;
        }
    }

    public static boolean isBuiltIn(String name) {
        return ORIGINAL.equalsIgnoreCase(name) || NO_AUTH.equalsIgnoreCase(name);
    }

    /** Called (on the caller's thread) after every change. */
    public void addListener(Runnable r) {
        if (r != null) listeners.add(r);
    }

    private void fire() {
        for (Runnable r : listeners) {
            try {
                r.run();
            } catch (RuntimeException ignored) {
                // a UI listener must not break the store
            }
        }
    }

    // ---- rule chains ---------------------------------------------------------------------

    /**
     * The rule chain that makes a request carry exactly this identity: strip every other confirmed
     * credential, then set each of its headers (added if missing) and cookies.
     */
    public static List<MatchReplaceRule> rulesFor(Identity id) {
        List<MatchReplaceRule> out = new ArrayList<>();
        out.add(MatchReplaceRule.stripAuthExcept(id.headers().keySet(), id.cookies().keySet()));
        for (Map.Entry<String, String> h : id.headers().entrySet()) {
            out.add(new MatchReplaceRule(MatchReplaceRule.Mode.HEADER, h.getKey(), "", false, h.getValue(), true));
        }
        for (Map.Entry<String, String> c : id.cookies().entrySet()) {
            out.add(MatchReplaceRule.cookie(c.getKey(), c.getValue()));
        }
        return out;
    }

    /** Strip every credential the request carries (the "No auth" identity): the whole Cookie header,
     * Authorization, and any other confirmed auth header. */
    public static List<MatchReplaceRule> removeAuthRules() {
        List<MatchReplaceRule> out = new ArrayList<>();
        out.add(new MatchReplaceRule(MatchReplaceRule.Mode.REMOVE_HEADER, "Cookie", "", false, "", false));
        out.add(new MatchReplaceRule(MatchReplaceRule.Mode.REMOVE_HEADER, "Authorization", "", false, "", false));
        out.add(MatchReplaceRule.stripAuthExcept(List.of(), List.of()));
        return out;
    }

    /** Rules for an identity by name: built-ins included (Original = no rules). Null when unknown. */
    public List<MatchReplaceRule> rulesForName(String name) {
        if (ORIGINAL.equalsIgnoreCase(name)) return List.of();
        if (NO_AUTH.equalsIgnoreCase(name)) return removeAuthRules();
        Identity id = get(name);
        return id == null ? null : rulesFor(id);
    }
}
