package com.reconhub.export;

import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;
import com.reconhub.model.ParameterInfo;
import com.reconhub.model.TechInfo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.TreeSet;

/**
 * Exports collected recon data as plain-text wordlists (one entry per line, sorted, deduplicated)
 * for use with external tools (ffuf, Intruder, etc.). Passive: reads the {@link DataStore} only.
 */
public final class WordlistExporter {

    public enum Kind { PATHS, PARAM_NAMES, HOSTS }

    private WordlistExporter() {}

    /** @return number of unique lines written. */
    public static int export(DataStore store, Path file, Kind kind) throws IOException {
        TreeSet<String> lines = new TreeSet<>();
        switch (kind) {
            case PATHS -> {
                for (Endpoint e : store.snapshotEndpoints()) {
                    add(lines, pathOnly(e.getPath()));
                }
            }
            case PARAM_NAMES -> {
                for (ParameterInfo p : store.snapshotParameters()) {
                    add(lines, p.getName());
                }
                for (Endpoint e : store.snapshotEndpoints()) {
                    for (String n : e.getParamNames()) {
                        add(lines, n);
                    }
                }
            }
            case HOSTS -> {
                for (Endpoint e : store.snapshotEndpoints()) {
                    add(lines, e.getHost());
                }
                for (TechInfo t : store.snapshotTech()) {
                    add(lines, t.getHost());
                }
            }
        }
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, String.join("\n", lines).getBytes(StandardCharsets.UTF_8));
        return lines.size();
    }

    private static void add(TreeSet<String> set, String s) {
        if (s != null) {
            String v = s.trim();
            if (!v.isEmpty()) {
                set.add(v);
            }
        }
    }

    /** Strips scheme+authority from an absolute-URL path (JS/spec links) so the list holds paths. */
    private static String pathOnly(String path) {
        if (path == null) {
            return "";
        }
        String p = path.trim();
        if (p.startsWith("http://") || p.startsWith("https://")) {
            int slash = p.indexOf('/', p.indexOf("://") + 3);
            return slash >= 0 ? p.substring(slash) : "/";
        }
        return p;
    }
}
