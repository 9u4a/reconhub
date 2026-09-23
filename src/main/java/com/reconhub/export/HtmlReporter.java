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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/** Renders the {@link DataStore} into a single self-contained HTML report from a template. */
public final class HtmlReporter {

    private HtmlReporter() {}

    public static void export(DataStore store, Path file) throws IOException {
        export(store, file, ReportOptions.all());
    }

    public static void export(DataStore store, Path file, ReportOptions options) throws IOException {
        String template = loadTemplate();
        String body = buildBody(store, options == null ? ReportOptions.all() : options);
        String html = template
                .replace("{{GENERATED_AT}}",
                        ZonedDateTime.now().format(DateTimeFormatter.RFC_1123_DATE_TIME))
                .replace("{{BODY}}", body);

        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, html.getBytes(StandardCharsets.UTF_8));
    }

    private static String loadTemplate() throws IOException {
        try (InputStream in = HtmlReporter.class.getResourceAsStream("/report/template.html")) {
            if (in == null) {
                throw new IOException("report template not found on classpath");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String buildBody(DataStore store, ReportOptions options) {
        StringBuilder b = new StringBuilder();
        summarySection(b, store, options);
        hostRiskSection(b, store, options);
        chartsSection(b, store);
        findingsSection(b, store, options);
        endpointsSection(b, store);
        parametersSection(b, store);
        jsSection(b, store);
        techSection(b, store);
        return b.toString();
    }

    private static void summarySection(StringBuilder b, DataStore store, ReportOptions options) {
        b.append("<section id=\"summary\"><h2>Summary</h2><div class=\"cards\">");
        card(b, store.getRequestsProcessed(), "Requests");
        card(b, store.snapshotEndpoints().size(), "Endpoints");
        card(b, store.snapshotParameters().size(), "Parameters");
        card(b, store.snapshotFindings().size(), "Findings");
        card(b, store.snapshotJsAssets().size(), "JS files");
        card(b, store.snapshotTech().size(), "Hosts");
        b.append("</div>");

        // Severity summary over the findings that pass the report filter.
        var shown = filtered(store.snapshotFindings(), options);
        java.util.EnumMap<Finding.Severity, Integer> sev =
                new java.util.EnumMap<>(Finding.Severity.class);
        for (Finding f : shown) {
            sev.merge(f.getSeverity(), 1, Integer::sum);
        }
        b.append("<div class=\"sevsummary\">");
        for (Finding.Severity s : Finding.Severity.values()) {
            b.append("<span class=\"sev ").append(s.name()).append("\">").append(s.name())
                    .append(' ').append(sev.getOrDefault(s, 0)).append("</span>");
        }
        b.append("</div>");

        // Category summary.
        java.util.EnumMap<FindingTaxonomy.Category, Integer> cat =
                new java.util.EnumMap<>(FindingTaxonomy.Category.class);
        for (Finding f : shown) {
            cat.merge(FindingTaxonomy.categoryOf(f.getType()), 1, Integer::sum);
        }
        b.append("<div class=\"sevsummary\">");
        for (FindingTaxonomy.Category c : FindingTaxonomy.Category.values()) {
            int n = cat.getOrDefault(c, 0);
            if (n > 0) {
                b.append("<span class=\"cat ").append(c.name()).append("\">")
                        .append(esc(c.label())).append(' ').append(n).append("</span>");
            }
        }
        b.append("</div></section>");
    }

    private static void hostRiskSection(StringBuilder b, DataStore store, ReportOptions options) {
        java.util.Map<String, int[]> byHost = new java.util.TreeMap<>();   // [ep, H, M, L, I]
        for (Endpoint e : store.snapshotEndpoints()) {
            hostRow(byHost, hostLabel(e.getHost()))[0]++;
        }
        for (Finding f : filtered(store.snapshotFindings(), options)) {
            hostRow(byHost, hostLabel(hostOf(f.getLocationUrl())))[1 + f.getSeverity().ordinal()]++;
        }
        b.append("<section id=\"hostrisk\"><h2>Host risk</h2>");
        if (byHost.isEmpty()) {
            b.append("<p class=\"muted\">No hosts.</p></section>");
            return;
        }
        java.util.List<Object[]> rows = new java.util.ArrayList<>();
        for (var e : byHost.entrySet()) {
            int[] c = e.getValue();
            int score = c[1] * 100 + c[2] * 10 + c[3];
            rows.add(new Object[]{e.getKey(), c[0], c[1], c[2], c[3], c[4], score});
        }
        rows.sort(java.util.Comparator.comparingInt((Object[] r) -> (int) r[6]).reversed()
                .thenComparing(r -> (int) r[1], java.util.Comparator.reverseOrder()));
        b.append("<table><thead><tr><th>Host</th><th>Endpoints</th><th>High</th><th>Medium</th>"
                + "<th>Low</th><th>Info</th><th>Score</th></tr></thead><tbody>");
        for (Object[] r : rows) {
            b.append("<tr><td>").append(esc((String) r[0])).append("</td><td>").append(r[1])
                    .append("</td><td>").append(r[2]).append("</td><td>").append(r[3])
                    .append("</td><td>").append(r[4]).append("</td><td>").append(r[5])
                    .append("</td><td><b>").append(r[6]).append("</b></td></tr>");
        }
        b.append("</tbody></table></section>");
    }

    private static int[] hostRow(java.util.Map<String, int[]> m, String host) {
        return m.computeIfAbsent(host, k -> new int[5]);
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

    private static void chartsSection(StringBuilder b, DataStore store) {
        b.append("<section id=\"charts\"><h2>Distribution</h2>");
        b.append("<div style=\"display:flex;gap:32px;flex-wrap:wrap\">");
        barBlock(b, "Top hosts", store.hostCounts(), 8);
        barBlock(b, "Status codes", store.statusCodeCounts(), 8);
        barBlock(b, "Content types", store.contentTypeCounts(), 8);
        b.append("</div></section>");
    }

    private static void findingsSection(StringBuilder b, DataStore store, ReportOptions options) {
        b.append("<section id=\"findings\"><h2>Findings &amp; Secrets</h2>");
        var findings = filtered(store.snapshotFindings(), options);
        if (findings.isEmpty()) {
            b.append("<p class=\"muted\">No findings.</p></section>");
            return;
        }
        b.append("<table id=\"findings-table\"><thead><tr><th>Severity</th><th>Category</th>"
                + "<th>Type</th><th>Value</th><th>Location</th><th>Evidence</th><th>Seen</th>"
                + "<th>Status</th></tr></thead><tbody>");
        for (Finding f : findings) {
            FindingTaxonomy.Category c = FindingTaxonomy.categoryOf(f.getType());
            b.append("<tr data-sev=\"").append(f.getSeverity().name())
                    .append("\" data-cat=\"").append(c.name())
                    .append("\" data-triage=\"").append(f.getTriage().name()).append("\">")
                    .append("<td><span class=\"sev ").append(f.getSeverity().name()).append("\">")
                    .append(f.getSeverity().name()).append("</span></td>")
                    .append("<td><span class=\"cat ").append(c.name()).append("\">")
                    .append(esc(c.label())).append("</span></td><td>")
                    .append(esc(f.getType())).append("</td><td><code>")
                    .append(esc(f.getMasked())).append("</code></td><td><code>")
                    .append(esc(f.getLocationUrl())).append("</code></td><td class=\"muted\">")
                    .append(esc(f.getEvidence())).append("</td><td>")
                    .append(f.getTimesSeen()).append("</td><td class=\"muted\">")
                    .append(esc(triageLabel(f.getTriage()))).append("</td></tr>");
        }
        b.append("</tbody></table></section>");
    }

    private static void endpointsSection(StringBuilder b, DataStore store) {
        b.append("<section id=\"endpoints\"><h2>Endpoints</h2>");
        var endpoints = store.snapshotEndpoints();
        if (endpoints.isEmpty()) {
            b.append("<p class=\"muted\">No endpoints.</p></section>");
            return;
        }
        b.append("<table><thead><tr><th>Method</th><th>Host</th><th>Path</th>"
                + "<th>Status</th><th>Content-Type</th><th>Params</th><th>Auth</th><th>Source</th></tr></thead><tbody>");
        for (Endpoint e : endpoints) {
            b.append("<tr><td><code>").append(esc(e.getMethod())).append("</code></td><td>")
                    .append(esc(e.getHost())).append("</td><td><code>")
                    .append(esc(e.getPath())).append("</code></td><td>")
                    .append(e.getLastStatusCode() == 0 ? "&ndash;" : e.getLastStatusCode())
                    .append("</td><td class=\"muted\">").append(esc(shortCt(e.getContentType())))
                    .append("</td><td>").append(e.getParamCount()).append("</td><td class=\"muted\">")
                    .append(esc(e.authStatus())).append("</td><td class=\"muted\">")
                    .append(esc(String.join(",", e.getSources()))).append("</td></tr>");
        }
        b.append("</tbody></table></section>");
    }

    private static void parametersSection(StringBuilder b, DataStore store) {
        b.append("<section id=\"parameters\"><h2>Parameters</h2>");
        var params = store.snapshotParameters();
        if (params.isEmpty()) {
            b.append("<p class=\"muted\">No parameters.</p></section>");
            return;
        }
        b.append("<table><thead><tr><th>Host</th><th>Endpoint</th><th>Type</th><th>Name</th>"
                + "<th>Class</th><th>Example</th><th>Reflected</th><th>Seen</th></tr></thead><tbody>");
        for (ParameterInfo p : params) {
            b.append("<tr><td>").append(esc(p.getHost())).append("</td><td><code>")
                    .append(esc(p.getEndpointPath())).append("</code></td><td><code>")
                    .append(p.getLocation().name()).append("</code></td><td>")
                    .append(esc(p.getName())).append("</td><td>");
            for (String cls : ParameterClassifier.classify(p.getName())) {
                b.append("<span class=\"tag\" style=\"color:var(--low)\">").append(esc(cls))
                        .append("</span>");
            }
            b.append("</td><td class=\"muted\"><code>")
                    .append(esc(p.getExampleValue())).append("</code></td><td>")
                    .append(p.isReflected() ? "<span class=\"yes\">yes</span>" : "&ndash;")
                    .append("</td><td>").append(p.getSeen()).append("</td></tr>");
        }
        b.append("</tbody></table></section>");
    }

    private static void jsSection(StringBuilder b, DataStore store) {
        b.append("<section id=\"js\"><h2>JavaScript Files</h2>");
        var assets = store.snapshotJsAssets();
        if (assets.isEmpty()) {
            b.append("<p class=\"muted\">No JS files collected.</p></section>");
            return;
        }
        b.append("<table><thead><tr><th>URL</th><th>Preview</th><th>Size</th><th>Endpoints</th>"
                + "<th>Secrets</th><th>Saved path</th></tr></thead><tbody>");
        for (JsAsset a : assets) {
            b.append("<tr><td><code>").append(esc(a.getUrl())).append("</code></td><td>")
                    .append(esc(a.getPreview())).append("</td><td>")
                    .append(humanBytes(a.getSizeBytes())).append("</td><td>")
                    .append(a.getExtractedEndpoints()).append("</td><td>")
                    .append(a.getExtractedSecrets()).append("</td><td class=\"muted\"><code>")
                    .append(esc(a.getSavedPath())).append("</code></td></tr>");
        }
        b.append("</tbody></table></section>");
    }

    private static void techSection(StringBuilder b, DataStore store) {
        b.append("<section id=\"tech\"><h2>Technologies &amp; Security Headers</h2>");
        var techs = store.snapshotTech();
        if (techs.isEmpty()) {
            b.append("<p class=\"muted\">No technology data.</p></section>");
            return;
        }
        b.append("<table><thead><tr><th>Host</th><th>Technologies</th>"
                + "<th>Missing security headers</th></tr></thead><tbody>");
        for (TechInfo t : techs) {
            b.append("<tr><td>").append(esc(t.getHost())).append("</td><td>");
            for (String tech : t.getTechnologies()) {
                b.append("<span class=\"tag\">").append(esc(tech)).append("</span>");
            }
            b.append("</td><td>");
            for (String h : t.getMissingSecurityHeaders()) {
                b.append("<span class=\"tag\" style=\"color:var(--medium)\">").append(esc(h))
                        .append("</span>");
            }
            b.append("</td></tr>");
        }
        b.append("</tbody></table></section>");
    }

    // ---- helpers --------------------------------------------------------

    private static java.util.List<Finding> filtered(java.util.List<Finding> findings,
                                                    ReportOptions options) {
        if (options == null) {
            return findings;
        }
        java.util.List<Finding> out = new java.util.ArrayList<>();
        for (Finding f : findings) {
            if (options.includes(f)) {
                out.add(f);
            }
        }
        return out;
    }

    private static void card(StringBuilder b, int n, String label) {
        b.append("<div class=\"card\"><div class=\"n\">").append(n)
                .append("</div><div class=\"l\">").append(esc(label)).append("</div></div>");
    }

    private static void barBlock(StringBuilder b, String title, Map<?, Integer> data, int limit) {
        b.append("<div style=\"flex:1;min-width:280px\"><h2 style=\"font-size:13px\">")
                .append(esc(title)).append("</h2>");
        int max = data.values().stream().mapToInt(Integer::intValue).max().orElse(1);
        int i = 0;
        for (Map.Entry<?, Integer> e : data.entrySet()) {
            if (i++ >= limit) {
                break;
            }
            int pct = Math.max(2, (int) (100.0 * e.getValue() / max));
            b.append("<div class=\"barrow\"><div class=\"lbl\">")
                    .append(esc(String.valueOf(e.getKey()))).append("</div>")
                    .append("<div class=\"bar\" style=\"width:").append(pct).append("%\"></div>")
                    .append("<div class=\"val\">").append(e.getValue()).append("</div></div>");
        }
        b.append("</div>");
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
        if (ct == null) {
            return "";
        }
        return ct.split(";")[0].trim();
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

    private static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
