package com.reconhub.export;

import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.analysis.ParameterClassifier;
import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import com.reconhub.model.ParameterInfo;
import com.reconhub.model.TechInfo;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;

/**
 * Renders the {@link DataStore} into a Markdown report (for pasting into tickets / docs). Sensitive
 * values are masked, matching the HTML report. Honors {@link ReportOptions} for finding filtering.
 */
public final class MarkdownReporter {

    private MarkdownReporter() {}

    public static void export(DataStore store, Path file) throws IOException {
        export(store, file, ReportOptions.all());
    }

    public static void export(DataStore store, Path file, ReportOptions options) throws IOException {
        ReportOptions opt = options == null ? ReportOptions.all() : options;
        StringBuilder b = new StringBuilder();
        b.append("# ReconHub Report\n\n")
                .append("_Generated ")
                .append(ZonedDateTime.now().format(DateTimeFormatter.RFC_1123_DATE_TIME))
                .append("_\n\n");

        summary(b, store, opt);
        hostRisk(b, store, opt);
        findings(b, store, opt);
        endpoints(b, store);
        parameters(b, store);
        jsFiles(b, store);
        tech(b, store);

        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, b.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static void summary(StringBuilder b, DataStore store, ReportOptions opt) {
        b.append("## Summary\n\n");
        b.append("| Metric | Count |\n| --- | --- |\n");
        row(b, "Requests", store.getRequestsProcessed());
        row(b, "Endpoints", store.snapshotEndpoints().size());
        row(b, "Parameters", store.snapshotParameters().size());
        row(b, "Findings", store.snapshotFindings().size());
        row(b, "JS files", store.snapshotJsAssets().size());
        row(b, "Hosts", store.snapshotTech().size());

        List<Finding> shown = filtered(store.snapshotFindings(), opt);
        EnumMap<Finding.Severity, Integer> sev = new EnumMap<>(Finding.Severity.class);
        for (Finding f : shown) {
            sev.merge(f.getSeverity(), 1, Integer::sum);
        }
        b.append("\n**Findings by severity:** ");
        List<String> parts = new ArrayList<>();
        for (Finding.Severity s : Finding.Severity.values()) {
            parts.add(s.name() + " " + sev.getOrDefault(s, 0));
        }
        b.append(String.join(" · ", parts)).append("\n\n");
    }

    private static void hostRisk(StringBuilder b, DataStore store, ReportOptions opt) {
        java.util.Map<String, int[]> byHost = new java.util.TreeMap<>();   // [ep, H, M, L, I]
        for (Endpoint e : store.snapshotEndpoints()) {
            byHost.computeIfAbsent(hostLabel(e.getHost()), k -> new int[5])[0]++;
        }
        for (Finding f : filtered(store.snapshotFindings(), opt)) {
            byHost.computeIfAbsent(hostLabel(hostOf(f.getLocationUrl())), k -> new int[5])
                    [1 + f.getSeverity().ordinal()]++;
        }
        b.append("## Host risk\n\n");
        if (byHost.isEmpty()) {
            b.append("_No hosts._\n\n");
            return;
        }
        java.util.List<Object[]> rows = new java.util.ArrayList<>();
        for (var e : byHost.entrySet()) {
            int[] c = e.getValue();
            rows.add(new Object[]{e.getKey(), c[0], c[1], c[2], c[3], c[4],
                    c[1] * 100 + c[2] * 10 + c[3]});
        }
        rows.sort(java.util.Comparator.comparingInt((Object[] r) -> (int) r[6]).reversed()
                .thenComparing(r -> (int) r[1], java.util.Comparator.reverseOrder()));
        b.append("| Host | Endpoints | High | Medium | Low | Info | Score |\n"
                + "| --- | --- | --- | --- | --- | --- | --- |\n");
        for (Object[] r : rows) {
            b.append("| ").append(md((String) r[0])).append(" | ").append(r[1]).append(" | ")
                    .append(r[2]).append(" | ").append(r[3]).append(" | ").append(r[4])
                    .append(" | ").append(r[5]).append(" | ").append(r[6]).append(" |\n");
        }
        b.append('\n');
    }

    private static String hostLabel(String host) {
        return host == null || host.isBlank() ? "(relative / JS)" : host;
    }

    private static String hostOf(String url) {
        if (url == null || url.isBlank()) {
            return "";
        }
        try {
            String h = java.net.URI.create(url).getHost();
            return h == null ? "" : h;
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static void findings(StringBuilder b, DataStore store, ReportOptions opt) {
        b.append("## Findings & Secrets\n\n");
        List<Finding> findings = filtered(store.snapshotFindings(), opt);
        if (findings.isEmpty()) {
            b.append("_No findings._\n\n");
            return;
        }
        b.append("| Severity | Category | Type | Value | Location | Evidence | Seen | Status |\n"
                + "| --- | --- | --- | --- | --- | --- | --- | --- |\n");
        for (Finding f : findings) {
            b.append("| ").append(f.getSeverity().name())
                    .append(" | ").append(md(FindingTaxonomy.labelOf(f.getType())))
                    .append(" | ").append(md(f.getType()))
                    .append(" | ").append(code(f.getMasked()))
                    .append(" | ").append(code(f.getLocationUrl()))
                    .append(" | ").append(md(f.getEvidence()))
                    .append(" | ").append(f.getTimesSeen())
                    .append(" | ").append(md(triageLabel(f.getTriage())))
                    .append(" |\n");
        }
        b.append('\n');
    }

    private static void endpoints(StringBuilder b, DataStore store) {
        b.append("## Endpoints\n\n");
        List<Endpoint> eps = store.snapshotEndpoints();
        if (eps.isEmpty()) {
            b.append("_No endpoints._\n\n");
            return;
        }
        b.append("| Method | Host | Path | Status | Content-Type | Params | Auth | Source |\n"
                + "| --- | --- | --- | --- | --- | --- | --- | --- |\n");
        for (Endpoint e : eps) {
            b.append("| ").append(md(e.getMethod()))
                    .append(" | ").append(md(e.getHost()))
                    .append(" | ").append(code(e.getPath()))
                    .append(" | ").append(e.getLastStatusCode() == 0 ? "–" : e.getLastStatusCode())
                    .append(" | ").append(md(shortCt(e.getContentType())))
                    .append(" | ").append(e.getParamCount())
                    .append(" | ").append(md(e.authStatus()))
                    .append(" | ").append(md(String.join(",", e.getSources())))
                    .append(" |\n");
        }
        b.append('\n');
    }

    private static void parameters(StringBuilder b, DataStore store) {
        b.append("## Parameters\n\n");
        List<ParameterInfo> params = store.snapshotParameters();
        if (params.isEmpty()) {
            b.append("_No parameters._\n\n");
            return;
        }
        b.append("| Host | Endpoint | Type | Name | Class | Example | Reflected | Seen |\n"
                + "| --- | --- | --- | --- | --- | --- | --- | --- |\n");
        for (ParameterInfo p : params) {
            b.append("| ").append(md(p.getHost()))
                    .append(" | ").append(code(p.getEndpointPath()))
                    .append(" | ").append(p.getLocation().name())
                    .append(" | ").append(md(p.getName()))
                    .append(" | ").append(md(ParameterClassifier.classifyJoined(p.getName())))
                    .append(" | ").append(code(p.getExampleValue()))
                    .append(" | ").append(p.isReflected() ? "yes" : "–")
                    .append(" | ").append(p.getSeen())
                    .append(" |\n");
        }
        b.append('\n');
    }

    private static void jsFiles(StringBuilder b, DataStore store) {
        b.append("## JavaScript Files\n\n");
        List<JsAsset> assets = store.snapshotJsAssets();
        if (assets.isEmpty()) {
            b.append("_No JS files collected._\n\n");
            return;
        }
        b.append("| URL | Preview | Size | Endpoints | Secrets | Saved path |\n"
                + "| --- | --- | --- | --- | --- | --- |\n");
        for (JsAsset a : assets) {
            b.append("| ").append(code(a.getUrl()))
                    .append(" | ").append(md(a.getPreview()))
                    .append(" | ").append(humanBytes(a.getSizeBytes()))
                    .append(" | ").append(a.getExtractedEndpoints())
                    .append(" | ").append(a.getExtractedSecrets())
                    .append(" | ").append(code(a.getSavedPath()))
                    .append(" |\n");
        }
        b.append('\n');
    }

    private static void tech(StringBuilder b, DataStore store) {
        b.append("## Technologies & Security Headers\n\n");
        List<TechInfo> techs = store.snapshotTech();
        if (techs.isEmpty()) {
            b.append("_No technology data._\n\n");
            return;
        }
        b.append("| Host | Technologies | Missing security headers |\n| --- | --- | --- |\n");
        for (TechInfo t : techs) {
            b.append("| ").append(md(t.getHost()))
                    .append(" | ").append(md(String.join(", ", t.getTechnologies())))
                    .append(" | ").append(md(String.join(", ", t.getMissingSecurityHeaders())))
                    .append(" |\n");
        }
        b.append('\n');
    }

    // ---- helpers --------------------------------------------------------

    private static List<Finding> filtered(List<Finding> findings, ReportOptions opt) {
        List<Finding> out = new ArrayList<>();
        for (Finding f : findings) {
            if (opt.includes(f)) {
                out.add(f);
            }
        }
        return out;
    }

    private static void row(StringBuilder b, String label, int n) {
        b.append("| ").append(label).append(" | ").append(n).append(" |\n");
    }

    /** Escapes Markdown table-hostile characters (pipe, newlines). */
    private static String md(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("|", "\\|")
                .replace("\r", " ").replace("\n", " ");
    }

    /** Inline-code wrap for a value (empty stays empty). */
    private static String code(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        return "`" + md(s).replace("`", "\\`") + "`";
    }

    private static String triageLabel(Finding.Triage t) {
        return switch (t) {
            case NEW -> "New";
            case REVIEWED -> "Reviewed";
            case CONFIRMED -> "Confirmed";
            case FALSE_POSITIVE -> "False positive";
        };
    }

    private static String shortCt(String ct) {
        return ct == null ? "" : ct.split(";")[0].trim();
    }

    private static String humanBytes(int n) {
        if (n < 1024) {
            return n + " B";
        }
        if (n < 1024 * 1024) {
            return (n / 1024) + " KB";
        }
        return String.format("%.1f MB", n / (1024.0 * 1024.0));
    }
}
