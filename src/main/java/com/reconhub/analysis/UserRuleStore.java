package com.reconhub.analysis;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.reconhub.model.Finding;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * User-defined secret/detection rules, editable at runtime and persisted across Burp restarts via
 * Montoya extension preferences. The compiled list is shared live with a {@code SecretScanner}, so
 * added/removed rules take effect on the next scanned response (and on the next site-map ingest).
 */
public final class UserRuleStore {

    private static final String PREF_KEY = "reconhub.userRules.v1";

    /** Editable rule record (also the persisted JSON shape). */
    public static final class UserRule {
        public String name;
        public String severity;   // HIGH | MEDIUM | LOW | INFO
        public String regex;

        public UserRule() {}

        public UserRule(String name, String severity, String regex) {
            this.name = name;
            this.severity = severity;
            this.regex = regex;
        }
    }

    private final MontoyaApi api;
    private final Gson gson = new Gson();
    private final List<UserRule> raw = new CopyOnWriteArrayList<>();
    // Same list instance handed to the scanner — mutated in place so updates apply live.
    private final List<PatternRegistry.SecretRule> compiled = new CopyOnWriteArrayList<>();

    public UserRuleStore(MontoyaApi api) {
        this.api = api;
        load();
    }

    /** Live compiled rules shared with the scanner (do not replace the reference). */
    public List<PatternRegistry.SecretRule> compiledRules() {
        return compiled;
    }

    public List<UserRule> rules() {
        return new ArrayList<>(raw);
    }

    /** @return null on success, or an error message (e.g. bad regex) on failure. */
    public synchronized String add(String name, String severity, String regex) {
        if (name == null || name.isBlank()) {
            return "Name is required.";
        }
        if (regex == null || regex.isBlank()) {
            return "Regex is required.";
        }
        try {
            Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            return "Invalid regex: " + e.getMessage();
        }
        raw.add(new UserRule(name.trim(), normalizeSeverity(severity), regex));
        recompile();
        save();
        return null;
    }

    public synchronized void removeAt(int index) {
        if (index >= 0 && index < raw.size()) {
            raw.remove(index);
            recompile();
            save();
        }
    }

    // ---- internals ------------------------------------------------------

    private void recompile() {
        List<PatternRegistry.SecretRule> next = new ArrayList<>();
        for (UserRule r : raw) {
            try {
                next.add(new PatternRegistry.SecretRule(
                        r.name, parseSeverity(r.severity), Pattern.compile(r.regex)));
            } catch (PatternSyntaxException ignored) {
                // skip a rule that no longer compiles; keep the rest
            }
        }
        compiled.clear();
        compiled.addAll(next);
    }

    private void load() {
        try {
            String json = api.persistence().preferences().getString(PREF_KEY);
            if (json != null && !json.isBlank()) {
                UserRule[] arr = gson.fromJson(json, UserRule[].class);
                if (arr != null) {
                    for (UserRule r : arr) {
                        if (r != null && r.name != null && r.regex != null) {
                            raw.add(r);
                        }
                    }
                }
            }
        } catch (RuntimeException e) {
            api.logging().logToError("ReconHub: failed to load user rules: " + e);
        }
        recompile();
    }

    private void save() {
        try {
            api.persistence().preferences().setString(PREF_KEY, gson.toJson(raw));
        } catch (RuntimeException e) {
            api.logging().logToError("ReconHub: failed to save user rules: " + e);
        }
    }

    private static String normalizeSeverity(String s) {
        return parseSeverity(s).name();
    }

    private static Finding.Severity parseSeverity(String s) {
        if (s == null) {
            return Finding.Severity.MEDIUM;
        }
        try {
            return Finding.Severity.valueOf(s.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return Finding.Severity.MEDIUM;
        }
    }
}
