package com.reconhub.active;

import com.google.gson.Gson;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The known-path wordlist to probe during a bruteforce run. Loads the bundled
 * {@code /wordlists/known-paths.json}; a custom file (one path per line, optionally
 * {@code path,tag}) can extend or replace it via {@link #loadCustomFile(Path)}.
 */
public final class KnownPaths {

    /** One wordlist entry. {@code tag} drives severity when a hit is recorded as a Finding:
     * {@code exposed} (sensitive file/config) &gt; {@code admin}/{@code api} (surface) &gt; {@code debug}. */
    public record Entry(String path, String tag) {}

    private final List<Entry> entries;
    private final List<String> loadErrors;

    private KnownPaths(List<Entry> entries, List<String> loadErrors) {
        this.entries = entries;
        this.loadErrors = loadErrors;
    }

    public static KnownPaths loadBundled() {
        List<Entry> out = new ArrayList<>();
        List<String> errs = new ArrayList<>();
        try (InputStream in = KnownPaths.class.getResourceAsStream("/wordlists/known-paths.json")) {
            if (in == null) {
                errs.add("missing /wordlists/known-paths.json");
            } else {
                Raw raw = new Gson().fromJson(new InputStreamReader(in, StandardCharsets.UTF_8), Raw.class);
                if (raw != null && raw.paths != null) {
                    for (Raw.P p : raw.paths) {
                        if (p != null && p.path != null && !p.path.isBlank()) {
                            out.add(new Entry(p.path, p.tag == null || p.tag.isBlank() ? "admin" : p.tag));
                        }
                    }
                }
            }
        } catch (Exception e) {
            errs.add("known-paths.json: " + e);
        }
        return new KnownPaths(out, errs);
    }

    /** Parses a custom wordlist file: one path per line, optional {@code ,tag} suffix. */
    public static List<Entry> loadCustomFile(Path file) throws IOException {
        List<Entry> out = new ArrayList<>();
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            String s = line.strip();
            if (s.isEmpty() || s.startsWith("#")) {
                continue;
            }
            int comma = s.indexOf(',');
            String path = (comma < 0 ? s : s.substring(0, comma)).strip();
            String tag = comma < 0 ? "admin" : s.substring(comma + 1).strip();
            if (!path.startsWith("/")) {
                path = "/" + path;
            }
            out.add(new Entry(path, tag.isEmpty() ? "admin" : tag));
        }
        return out;
    }

    public List<Entry> entries() { return entries; }
    public List<String> loadErrors() { return loadErrors; }

    private static final class Raw {
        List<P> paths;
        static final class P { String path; String tag; }
    }
}
