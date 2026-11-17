package com.reconhub.ui;

import com.reconhub.analysis.FindingHints;
import com.reconhub.model.ClientFlow;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Data behind the JS Assets detail tabs (0.63.0): header badges and one row list per tab (Findings,
 * Client Flows, Notes, Endpoints, File). No Swing -- headless-tested; {@link JsInfoPanel} renders it.
 */
final class JsInfoContent {

    /** A header badge; {@code warn} = highlighted (library, high risk). */
    record Badge(String text, boolean warn) {}

    record FindingRow(Finding.Severity severity, String type, String value, String hint) {}

    record FlowRow(String method, String path, String bodyKeys, String auth, String trigger, String function) {}

    /** {@code kind}: "Possible flow" / "Possible pair" / a code-pattern rule name / "Info". */
    record NoteRow(String kind, String detail, String hint) {}

    record Content(String title, String url, List<Badge> badges, String libraryNote, List<FindingRow> findings,
                   List<FlowRow> flows, List<NoteRow> notes, List<String> endpoints, List<String[]> file) {}

    record Input(JsAsset asset, List<Finding> findings, List<ClientFlow> flows, List<Endpoint> endpoints, int risk) {}

    private JsInfoContent() {}

    static Content build(Input in) {
        JsAsset a = in.asset();
        List<Badge> badges = new ArrayList<>();
        if (a.isLibrary()) badges.add(new Badge(a.getKind(), true));
        badges.add(new Badge(kb(a.getSizeBytes()), false));
        if (in.risk() > 0) badges.add(new Badge("Risk " + in.risk(), in.risk() >= 10));

        List<FindingRow> findings = new ArrayList<>();
        List<Finding> sorted = new ArrayList<>(in.findings());
        sorted.sort(Comparator.comparing(Finding::getSeverity).thenComparing(Finding::getType));
        for (Finding f : sorted) {
            findings.add(new FindingRow(f.getSeverity(), f.getType(), valueOf(f), FindingHints.of(f)));
        }

        List<FlowRow> flows = new ArrayList<>();
        for (ClientFlow f : in.flows()) {
            flows.add(new FlowRow(f.getMethod(), f.getPath(), String.join(", ", f.getBodyKeys()),
                    f.getAuth().isEmpty() ? "(none)" : f.getAuth(), f.getTrigger(), f.getFunction()));
        }

        List<String> endpoints = new ArrayList<>();
        for (Endpoint e : in.endpoints()) endpoints.add(e.getNormalizedUrl());

        List<String[]> file = List.of(
                new String[]{"URL", a.getUrl()},
                new String[]{"SHA-256", a.getSha256()},
                new String[]{"Size", a.getSizeBytes() + " chars (" + kb(a.getSizeBytes()) + ")"},
                new String[]{"Kind", a.isLibrary() ? a.getKind() : "app code"},
                new String[]{"Preview", a.getPreview().isEmpty() ? "(none)" : a.getPreview()},
                new String[]{"Saved", a.getSavedPath().isEmpty() ? "(not saved)" : a.getSavedPath()});

        String libNote = a.isLibrary()
                ? "Library / third-party code -- deep analysis is skipped unless enabled in Settings › JavaScript" : "";
        return new Content(fileName(a.getUrl()), a.getUrl(), badges, libNote, findings, flows,
                notes(a.getNotes()), endpoints, file);
    }

    /**
     * Value column: the masked match for a sensitive finding; otherwise the evidence text without its
     * "Try:" part (a JS / HTML comment's text lives only there -- its rawMatch is a dedup hash).
     * Empty when the type already names the value ("Hidden parameter in JS: debug").
     */
    static String valueOf(Finding f) {
        String raw = f.getRawMatch() == null ? "" : f.getRawMatch();
        if (!raw.isEmpty() && f.getType().endsWith(raw)) return "";
        String v = f.getMasked() == null ? "" : f.getMasked();
        if (v.isEmpty() && !f.isSensitive() && f.getEvidence() != null) {
            v = f.getEvidence();
            int tryAt = v.indexOf("  |  Try: ");
            if (tryAt >= 0) v = v.substring(0, tryAt);
        }
        return v.replaceAll("\\s+", " ").trim();
    }

    /** Splits the analyzer's note strings into kind / detail / hint. */
    static List<NoteRow> notes(List<String> notes) {
        List<NoteRow> out = new ArrayList<>();
        for (String n : notes) {
            if (n.startsWith("Unproven flow:")) {
                out.add(new NoteRow("Possible flow", n.substring("Unproven flow:".length()).trim(),
                        "check by hand whether the source value really reaches the sink"));
            } else if (n.startsWith("Unlinked:")) {
                out.add(new NoteRow("Possible pair", n.substring("Unlinked:".length()).trim(),
                        "check by hand whether this value belongs to the matched logic"));
            } else if (n.contains(": ") && !n.startsWith("File too large")) {
                int colon = n.indexOf(": ");
                int tryAt = n.indexOf("  |  Try: ");
                String detail = tryAt > colon ? n.substring(colon + 2, tryAt) : n.substring(colon + 2);
                String hint = tryAt > colon ? n.substring(tryAt + "  |  Try: ".length()) : "";
                out.add(new NoteRow(n.substring(0, colon), detail.trim(), hint));
            } else {
                out.add(new NoteRow("Info", n, ""));
            }
        }
        return out;
    }

    static String fileName(String url) {
        if (url == null || url.isBlank()) return "(unknown)";
        String u = url;
        int q = u.indexOf('?');
        if (q >= 0) u = u.substring(0, q);
        int s = u.lastIndexOf('/');
        String n = s >= 0 ? u.substring(s + 1) : u;
        return n.isBlank() ? url : n;
    }

    static String kb(int chars) {
        return chars < 1024 ? chars + " B" : String.format(Locale.ROOT, "%.1f KB", chars / 1024.0);
    }
}
