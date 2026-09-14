package com.reconhub.export;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;
import com.reconhub.model.JsAsset;
import com.reconhub.model.ParameterInfo;
import com.reconhub.model.TechInfo;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Saves and restores the full {@link DataStore} to/from a versioned JSON <em>state</em> file
 * (distinct from the human-readable report). Intended for backup and moving a project between
 * machines. Optionally embeds the raw request/response bytes (base64) so the message viewer and
 * body search keep working after an import.
 */
public final class StateSerializer {

    public static final String FORMAT = "reconhub-state";
    public static final int VERSION = 1;

    private static final Gson GSON =
            new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private StateSerializer() {}

    // ---- DTOs -----------------------------------------------------------

    private static final class State {
        String format;
        int version;
        String exportedAt;
        boolean includesMessages;
        Counters counters;
        List<EndpointDto> endpoints;
        List<ParameterDto> parameters;
        List<FindingDto> findings;
        List<JsAssetDto> jsAssets;
        List<TechDto> tech;
    }

    private static final class Counters {
        int requestsProcessed;
        Map<Integer, Integer> statusCodeCounts;
        Map<String, Integer> hostCounts;
        Map<String, Integer> contentTypeCounts;
    }

    private static final class EndpointDto {
        String method, host, path, normalizedUrl, contentType;
        int status, observations;
        long firstSeen;
        List<String> paramNames, sources, origins;
        String reqB64, respB64;
    }

    private static final class ParameterDto {
        String location, name, endpointKey, endpointPath, exampleValue;
        boolean reflected;
        int seen;
        String reqB64, respB64;
    }

    private static final class FindingDto {
        String type, severity, rawMatch, location, evidence;
        int timesSeen;
        boolean sensitive;
        String reqB64, respB64;
    }

    private static final class JsAssetDto {
        String url, sha256, savedPath;
        int sizeBytes, extractedEndpoints, extractedSecrets;
    }

    private static final class TechDto {
        String host;
        List<String> technologies, missingSecurityHeaders;
    }

    // ---- Export ---------------------------------------------------------

    public static void export(DataStore store, Path file, boolean includeMessages)
            throws IOException {
        State s = new State();
        s.format = FORMAT;
        s.version = VERSION;
        s.exportedAt = Instant.now().toString();
        s.includesMessages = includeMessages;

        s.counters = new Counters();
        s.counters.requestsProcessed = store.getRequestsProcessed();
        s.counters.statusCodeCounts = store.statusCodeCounts();
        s.counters.hostCounts = store.hostCounts();
        s.counters.contentTypeCounts = store.contentTypeCounts();

        s.endpoints = new ArrayList<>();
        for (Endpoint e : store.snapshotEndpoints()) {
            EndpointDto d = new EndpointDto();
            d.method = e.getMethod();
            d.host = e.getHost();
            d.path = e.getPath();
            d.normalizedUrl = e.getNormalizedUrl();
            d.status = e.getLastStatusCode();
            d.contentType = e.getContentType();
            d.observations = e.getObservations();
            d.firstSeen = e.getFirstSeenEpochMs();
            d.paramNames = new ArrayList<>(e.getParamNames());
            d.sources = new ArrayList<>(e.getSources());
            d.origins = new ArrayList<>(e.getOrigins());
            if (includeMessages) {
                String[] msg = dumpMessages(e.getMessages());
                if (msg != null) {
                    d.reqB64 = msg[0];
                    d.respB64 = msg[1];
                }
            }
            s.endpoints.add(d);
        }

        s.parameters = new ArrayList<>();
        for (ParameterInfo p : store.snapshotParameters()) {
            ParameterDto d = new ParameterDto();
            d.location = p.getLocation().name();
            d.name = p.getName();
            d.endpointKey = p.getEndpointKey();
            d.endpointPath = p.getEndpointPath();
            d.exampleValue = p.getExampleValue();
            d.reflected = p.isReflected();
            d.seen = p.getSeen();
            if (includeMessages) {
                String[] msg = dumpMessages(p.getMessages());
                if (msg != null) {
                    d.reqB64 = msg[0];
                    d.respB64 = msg[1];
                }
            }
            s.parameters.add(d);
        }

        s.findings = new ArrayList<>();
        for (Finding f : store.snapshotFindings()) {
            FindingDto d = new FindingDto();
            d.type = f.getType();
            d.severity = f.getSeverity().name();
            d.rawMatch = f.getRawMatch();
            d.location = f.getLocationUrl();
            d.evidence = f.getEvidence();
            d.timesSeen = f.getTimesSeen();
            d.sensitive = f.isSensitive();
            if (includeMessages) {
                String[] msg = dumpMessages(f.getMessages());
                if (msg != null) {
                    d.reqB64 = msg[0];
                    d.respB64 = msg[1];
                }
            }
            s.findings.add(d);
        }

        s.jsAssets = new ArrayList<>();
        for (JsAsset a : store.snapshotJsAssets()) {
            JsAssetDto d = new JsAssetDto();
            d.url = a.getUrl();
            d.sha256 = a.getSha256();
            d.sizeBytes = a.getSizeBytes();
            d.extractedEndpoints = a.getExtractedEndpoints();
            d.extractedSecrets = a.getExtractedSecrets();
            d.savedPath = a.getSavedPath();
            s.jsAssets.add(d);
        }

        s.tech = new ArrayList<>();
        for (TechInfo t : store.snapshotTech()) {
            TechDto d = new TechDto();
            d.host = t.getHost();
            d.technologies = new ArrayList<>(t.getTechnologies());
            d.missingSecurityHeaders = new ArrayList<>(t.getMissingSecurityHeaders());
            s.tech.add(d);
        }

        Files.createDirectories(file.toAbsolutePath().getParent());
        Files.write(file, GSON.toJson(s).getBytes(StandardCharsets.UTF_8));
    }

    // ---- Import ---------------------------------------------------------

    /** @return a short summary of what was imported. */
    public static String importInto(DataStore store, Path file, boolean clearFirst)
            throws IOException {
        State s;
        try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            s = GSON.fromJson(r, State.class);
        }
        if (s == null || !FORMAT.equals(s.format)) {
            throw new IOException("Not a ReconHub state file (missing/invalid \"format\").");
        }
        if (s.version > VERSION) {
            throw new IOException("State file version " + s.version
                    + " is newer than supported (" + VERSION + "). Update the extension.");
        }
        if (clearFirst) {
            store.clear();
        }

        int endpoints = 0, params = 0, findings = 0, js = 0, tech = 0;

        if (s.endpoints != null) {
            for (EndpointDto d : s.endpoints) {
                Endpoint e = new Endpoint(d.method, d.host, d.path, d.normalizedUrl, d.firstSeen);
                e.setLastStatusCode(d.status);
                e.setContentType(d.contentType);
                e.setObservations(d.observations);
                e.addParamNames(new TreeSet<>(nz(d.paramNames)));
                e.addSources(new TreeSet<>(nz(d.sources)));
                e.addOrigins(new TreeSet<>(nz(d.origins)));
                e.setMessages(rebuildMessages(d.reqB64, d.respB64));
                store.restoreEndpoint(e);
                endpoints++;
            }
        }
        if (s.parameters != null) {
            for (ParameterDto d : s.parameters) {
                ParameterInfo p = new ParameterInfo(
                        parseLocation(d.location), d.name, d.endpointKey, d.endpointPath);
                p.setExampleValue(d.exampleValue);
                p.setReflected(d.reflected);
                p.setSeen(d.seen);
                p.setMessages(rebuildMessages(d.reqB64, d.respB64));
                store.restoreParameter(p);
                params++;
            }
        }
        if (s.findings != null) {
            for (FindingDto d : s.findings) {
                Finding f = new Finding(d.type, parseSeverity(d.severity), d.rawMatch,
                        d.location, d.evidence, d.sensitive);
                f.setTimesSeen(d.timesSeen);
                f.setMessages(rebuildMessages(d.reqB64, d.respB64));
                store.restoreFinding(f);
                findings++;
            }
        }
        if (s.jsAssets != null) {
            for (JsAssetDto d : s.jsAssets) {
                JsAsset a = new JsAsset(d.url, d.sha256, d.sizeBytes);
                a.setExtractedEndpoints(d.extractedEndpoints);
                a.setExtractedSecrets(d.extractedSecrets);
                a.setSavedPath(d.savedPath == null ? "" : d.savedPath);
                store.restoreJsAsset(a);
                js++;
            }
        }
        if (s.tech != null) {
            for (TechDto d : s.tech) {
                TechInfo t = new TechInfo(d.host);
                for (String tech1 : nz(d.technologies)) {
                    t.addTechnology(tech1);
                }
                t.setMissingSecurityHeaders(new TreeSet<>(nz(d.missingSecurityHeaders)));
                store.restoreTech(t);
                tech++;
            }
        }
        if (s.counters != null) {
            store.restoreCounters(s.counters.requestsProcessed, s.counters.statusCodeCounts,
                    s.counters.hostCounts, s.counters.contentTypeCounts);
        }

        store.fireChanged();
        return String.format("Imported %d endpoints, %d parameters, %d findings, %d JS, %d hosts%s.",
                endpoints, params, findings, js, tech,
                s.includesMessages ? " (with messages)" : "");
    }

    // ---- Message round-trip ---------------------------------------------

    /** @return {reqB64, respB64(nullable)} or null when there is no request to dump. */
    private static String[] dumpMessages(HttpRequestResponse rr) {
        if (rr == null || rr.request() == null) {
            return null;
        }
        String reqB64 = Base64.getEncoder().encodeToString(rr.request().toByteArray().getBytes());
        String respB64 = rr.response() != null
                ? Base64.getEncoder().encodeToString(rr.response().toByteArray().getBytes())
                : null;
        return new String[]{reqB64, respB64};
    }

    private static HttpRequestResponse rebuildMessages(String reqB64, String respB64) {
        if (reqB64 == null) {
            return null;
        }
        try {
            HttpRequest req = HttpRequest.httpRequest(
                    ByteArray.byteArray(Base64.getDecoder().decode(reqB64)));
            HttpResponse resp = respB64 != null
                    ? HttpResponse.httpResponse(ByteArray.byteArray(Base64.getDecoder().decode(respB64)))
                    : HttpResponse.httpResponse();
            return HttpRequestResponse.httpRequestResponse(req, resp);
        } catch (RuntimeException e) {
            return null;   // corrupt base64 -> just drop the message, keep the row
        }
    }

    // ---- helpers --------------------------------------------------------

    private static List<String> nz(List<String> l) {
        return l == null ? List.of() : l;
    }

    private static ParameterInfo.Location parseLocation(String s) {
        try {
            return ParameterInfo.Location.valueOf(s);
        } catch (RuntimeException e) {
            return ParameterInfo.Location.QUERY;
        }
    }

    private static Finding.Severity parseSeverity(String s) {
        try {
            return Finding.Severity.valueOf(s);
        } catch (RuntimeException e) {
            return Finding.Severity.INFO;
        }
    }
}
