package com.reconhub.export;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
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
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Serializes the whole {@link DataStore} to a structured JSON file (for external post-processing). */
public final class JsonExporter {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private JsonExporter() {}

    public static void export(DataStore store, Path file) throws IOException {
        export(store, file, ReportOptions.all());
    }

    /** As {@link #export(DataStore, Path)}, but every section is filtered by {@code opts} first (see
     * {@link ReportData}) -- covers both the finding-triage options and (0.41.0) bookmarked-only across
     * all five row types. */
    public static void export(DataStore store, Path file, ReportOptions opts) throws IOException {
        ReportOptions o = opts == null ? ReportOptions.all() : opts;
        ReportData data = ReportData.of(store, o);
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("generatedAt", Instant.now().toString());
        root.put("summary", summary(store, data));
        root.put("endpoints", endpoints(data));
        root.put("parameters", parameters(data));
        root.put("findings", findings(data));
        root.put("jsAssets", jsAssets(data));
        root.put("technologies", technologies(data));

        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, GSON.toJson(root).getBytes(StandardCharsets.UTF_8));
    }

    private static Map<String, Object> summary(DataStore store, ReportData data) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("requestsProcessed", store.getRequestsProcessed());
        m.put("endpointCount", data.endpoints().size());
        m.put("parameterCount", data.parameters().size());
        m.put("findingCount", data.findings().size());
        m.put("jsAssetCount", data.jsAssets().size());
        m.put("hostCount", data.tech().size());
        m.put("statusCodeCounts", store.statusCodeCounts());
        m.put("hostCounts", store.hostCounts());
        m.put("contentTypeCounts", store.contentTypeCounts());
        return m;
    }

    private static List<Map<String, Object>> endpoints(ReportData data) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Endpoint e : data.endpoints()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("method", e.getMethod());
            m.put("host", e.getHost());
            m.put("path", e.getPath());
            m.put("normalizedUrl", e.getNormalizedUrl());
            m.put("status", e.getLastStatusCode());
            m.put("contentType", e.getContentType());
            m.put("paramNames", e.getParamNames());
            m.put("sources", e.getSources());
            m.put("origins", e.getOrigins());
            m.put("observations", e.getObservations());
            out.add(m);
        }
        return out;
    }

    private static List<Map<String, Object>> parameters(ReportData data) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (ParameterInfo p : data.parameters()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("host", p.getHost());
            m.put("endpoint", p.getEndpointPath());
            m.put("type", p.getLocation().name());
            m.put("name", p.getName());
            m.put("classes", ParameterClassifier.classifyCached(p.getName()));   // cached (0.43.7)
            m.put("exampleValue", p.getExampleValue());
            m.put("reflected", p.isReflected());
            m.put("seen", p.getSeen());
            out.add(m);
        }
        return out;
    }

    private static List<Map<String, Object>> findings(ReportData data) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Finding f : data.findings()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("type", f.getType());
            m.put("category", FindingTaxonomy.categoryOf(f.getType()).label());
            m.put("severity", f.getSeverity().name());
            m.put("value", f.getMasked());
            m.put("location", f.getLocationUrl());
            m.put("evidence", f.getEvidence());
            m.put("timesSeen", f.getTimesSeen());
            m.put("triage", f.getTriage().name());
            out.add(m);
        }
        return out;
    }

    private static List<Map<String, Object>> jsAssets(ReportData data) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (JsAsset a : data.jsAssets()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("url", a.getUrl());
            m.put("sha256", a.getSha256());
            m.put("sizeBytes", a.getSizeBytes());
            m.put("preview", a.getPreview());
            m.put("extractedEndpoints", a.getExtractedEndpoints());
            m.put("extractedSecrets", a.getExtractedSecrets());
            m.put("savedPath", a.getSavedPath());
            out.add(m);
        }
        return out;
    }

    private static List<Map<String, Object>> technologies(ReportData data) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (TechInfo t : data.tech()) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("host", t.getHost());
            m.put("technologies", t.getTechnologies());
            m.put("missingSecurityHeaders", t.getMissingSecurityHeaders());
            out.add(m);
        }
        return out;
    }
}
