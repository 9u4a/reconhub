package com.reconhub.export;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.core.DataStore;
import com.reconhub.core.HashUtil;
import com.reconhub.model.Finding;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Exports findings as SARIF 2.1.0 (for CI ingestion / code-scanning dashboards). Values are never
 * emitted raw — messages use the masked value and evidence, so no secret is written to the report.
 */
public final class SarifExporter {

    private static final String SCHEMA =
            "https://json.schemastore.org/sarif-2.1.0.json";

    private SarifExporter() {}

    public static void export(DataStore store, Path file) throws IOException {
        export(store, file, ReportOptions.all());
    }

    public static void export(DataStore store, Path file, ReportOptions options) throws IOException {
        ReportOptions opt = options == null ? ReportOptions.all() : options;

        JsonArray results = new JsonArray();
        Map<String, JsonObject> rules = new LinkedHashMap<>();   // ruleId(type) -> rule object

        List<Finding> findings = store.snapshotFindings();
        for (Finding f : findings) {
            if (!opt.includes(f)) {
                continue;
            }
            String ruleId = f.getType();
            rules.computeIfAbsent(ruleId, id -> {
                JsonObject rule = new JsonObject();
                rule.addProperty("id", id);
                rule.addProperty("name", id);
                JsonObject sd = new JsonObject();
                sd.addProperty("text", id + " (" + FindingTaxonomy.labelOf(id) + ")");
                rule.add("shortDescription", sd);
                return rule;
            });
            results.add(result(f, ruleId));
        }

        JsonObject driver = new JsonObject();
        driver.addProperty("name", "ReconHub");
        driver.addProperty("informationUri", "https://portswigger.net/burp");
        JsonArray ruleArr = new JsonArray();
        rules.values().forEach(ruleArr::add);
        driver.add("rules", ruleArr);

        JsonObject tool = new JsonObject();
        tool.add("driver", driver);

        JsonObject run = new JsonObject();
        run.add("tool", tool);
        run.add("results", results);

        JsonArray runs = new JsonArray();
        runs.add(run);

        JsonObject root = new JsonObject();
        root.addProperty("$schema", SCHEMA);
        root.addProperty("version", "2.1.0");
        root.add("runs", runs);

        Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, gson.toJson(root).getBytes(StandardCharsets.UTF_8));
    }

    private static JsonObject result(Finding f, String ruleId) {
        JsonObject r = new JsonObject();
        r.addProperty("ruleId", ruleId);
        r.addProperty("level", level(f.getSeverity()));

        JsonObject msg = new JsonObject();
        msg.addProperty("text", message(f));
        r.add("message", msg);

        String url = f.getLocationUrl();
        if (url != null && !url.isBlank()) {
            JsonObject artifact = new JsonObject();
            artifact.addProperty("uri", url);
            JsonObject phys = new JsonObject();
            phys.add("artifactLocation", artifact);
            JsonObject loc = new JsonObject();
            loc.add("physicalLocation", phys);
            JsonArray locs = new JsonArray();
            locs.add(loc);
            r.add("locations", locs);
        }

        // Fingerprint keeps the same finding stable across runs (dedup in CI). Hashed so the raw
        // matched value (which f.key() embeds) is never written to the report.
        JsonObject fp = new JsonObject();
        fp.addProperty("reconhub/v1", HashUtil.sha256(f.key()));
        r.add("partialFingerprints", fp);
        return r;
    }

    /** Human-readable message without leaking a raw secret value. */
    private static String message(Finding f) {
        StringBuilder sb = new StringBuilder(f.getType());
        String val = f.isSensitive() ? f.getMasked() : "";
        if (val != null && !val.isBlank()) {
            sb.append(" — ").append(val);
        }
        if (f.getEvidence() != null && !f.getEvidence().isBlank()) {
            sb.append(" (").append(f.getEvidence()).append(')');
        }
        return sb.toString();
    }

    private static String level(Finding.Severity sev) {
        return switch (sev) {
            case HIGH -> "error";
            case MEDIUM -> "warning";
            case LOW, INFO -> "note";
        };
    }
}
