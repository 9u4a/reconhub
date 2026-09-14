package com.reconhub.analysis;

import com.google.gson.Gson;
import com.reconhub.model.Finding;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Loads and compiles the regex rule sets from {@code resources/patterns/*.json} once at startup.
 * All compiled {@link Pattern}s are reused across the whole run (compile-once).
 */
public final class PatternRegistry {

    // ---- Compiled rule types --------------------------------------------

    public static final class SecretRule {
        public final String name;
        public final Finding.Severity severity;
        public final Pattern pattern;

        SecretRule(String name, Finding.Severity severity, Pattern pattern) {
            this.name = name;
            this.severity = severity;
            this.pattern = pattern;
        }
    }

    public static final class JsLinkRule {
        public final String name;
        public final Pattern pattern;

        JsLinkRule(String name, Pattern pattern) {
            this.name = name;
            this.pattern = pattern;
        }
    }

    public static final class TechRule {
        public final String source;   // header | cookie | body
        public final String header;   // for source == header
        public final Pattern match;
        public final String tech;     // may contain $1 backreference

        TechRule(String source, String header, Pattern match, String tech) {
            this.source = source;
            this.header = header;
            this.match = match;
            this.tech = tech;
        }
    }

    private final List<SecretRule> secretRules = new ArrayList<>();
    private final List<SecretRule> signatureRules = new ArrayList<>();   // interesting-response signatures
    private final List<JsLinkRule> jsLinkRules = new ArrayList<>();
    private final List<TechRule> techRules = new ArrayList<>();
    private final List<String> securityHeaders = new ArrayList<>();
    private final List<String> loadErrors = new ArrayList<>();

    public List<SecretRule> secretRules() { return secretRules; }
    public List<SecretRule> signatureRules() { return signatureRules; }
    public List<JsLinkRule> jsLinkRules() { return jsLinkRules; }
    public List<TechRule> techRules() { return techRules; }
    public List<String> securityHeaders() { return securityHeaders; }
    public List<String> loadErrors() { return loadErrors; }

    /** Loads all pattern files from the classpath; collects (never throws) per-rule errors. */
    public static PatternRegistry load() {
        PatternRegistry r = new PatternRegistry();
        Gson gson = new Gson();
        r.loadSecrets(gson);
        r.loadSignatures(gson);
        r.loadJsLinks(gson);
        r.loadTech(gson);
        return r;
    }

    // ---- JSON DTOs ------------------------------------------------------

    private static final class SecretsFile {
        List<Raw> patterns;
        static final class Raw { String name; String severity; String regex; }
    }

    private static final class JsFile {
        List<Raw> patterns;
        static final class Raw { String name; String regex; }
    }

    private static final class TechFile {
        List<String> securityHeaders;
        List<Raw> rules;
        static final class Raw { String source; String header; String match; String tech; }
    }

    // ---- Loading --------------------------------------------------------

    private void loadSecrets(Gson gson) {
        SecretsFile f = read(gson, "/patterns/secrets.json", SecretsFile.class);
        if (f == null || f.patterns == null) {
            return;
        }
        for (SecretsFile.Raw raw : f.patterns) {
            try {
                Finding.Severity sev = parseSeverity(raw.severity);
                secretRules.add(new SecretRule(raw.name, sev, Pattern.compile(raw.regex)));
            } catch (PatternSyntaxException e) {
                loadErrors.add("secrets[" + raw.name + "]: " + e.getMessage());
            }
        }
    }

    private void loadSignatures(Gson gson) {
        SecretsFile f = read(gson, "/patterns/interesting.json", SecretsFile.class);
        if (f == null || f.patterns == null) {
            return;
        }
        for (SecretsFile.Raw raw : f.patterns) {
            try {
                Finding.Severity sev = parseSeverity(raw.severity);
                signatureRules.add(new SecretRule(raw.name, sev, Pattern.compile(raw.regex)));
            } catch (PatternSyntaxException e) {
                loadErrors.add("interesting[" + raw.name + "]: " + e.getMessage());
            }
        }
    }

    private void loadJsLinks(Gson gson) {
        JsFile f = read(gson, "/patterns/js-endpoints.json", JsFile.class);
        if (f == null || f.patterns == null) {
            return;
        }
        for (JsFile.Raw raw : f.patterns) {
            try {
                jsLinkRules.add(new JsLinkRule(raw.name, Pattern.compile(raw.regex)));
            } catch (PatternSyntaxException e) {
                loadErrors.add("js-endpoints[" + raw.name + "]: " + e.getMessage());
            }
        }
    }

    private void loadTech(Gson gson) {
        TechFile f = read(gson, "/patterns/tech-signatures.json", TechFile.class);
        if (f == null) {
            return;
        }
        if (f.securityHeaders != null) {
            securityHeaders.addAll(f.securityHeaders);
        }
        if (f.rules == null) {
            return;
        }
        for (TechFile.Raw raw : f.rules) {
            try {
                String regex = raw.match == null ? ".*" : raw.match;
                techRules.add(new TechRule(raw.source, raw.header, Pattern.compile(regex), raw.tech));
            } catch (PatternSyntaxException e) {
                loadErrors.add("tech[" + raw.tech + "]: " + e.getMessage());
            }
        }
    }

    private <T> T read(Gson gson, String resourcePath, Class<T> type) {
        try (InputStream in = PatternRegistry.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                loadErrors.add("resource not found: " + resourcePath);
                return null;
            }
            return gson.fromJson(new InputStreamReader(in, StandardCharsets.UTF_8), type);
        } catch (Exception e) {
            loadErrors.add(resourcePath + ": " + e.getMessage());
            return null;
        }
    }

    private static Finding.Severity parseSeverity(String s) {
        if (s == null) {
            return Finding.Severity.INFO;
        }
        try {
            return Finding.Severity.valueOf(s.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return Finding.Severity.INFO;
        }
    }
}
