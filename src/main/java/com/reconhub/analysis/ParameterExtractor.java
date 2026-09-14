package com.reconhub.analysis;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.reconhub.core.DataStore;
import com.reconhub.model.ParameterInfo;

import java.util.Map;

/**
 * Extracts parameters from a request (query / body / cookie / JSON keys) and records them in the
 * {@link DataStore}, flagging values that are reflected in the response body.
 */
public final class ParameterExtractor {

    private final DataStore store;

    public ParameterExtractor(DataStore store) {
        this.store = store;
    }

    public void extract(HttpRequest request, String endpointKey, String endpointPath,
                        String responseBody, HttpRequestResponse messages) {
        String respBody = responseBody == null ? "" : responseBody;

        for (ParsedHttpParameter p : request.parameters()) {
            ParameterInfo.Location loc = mapLocation(p.type());
            if (loc == null) {
                continue;
            }
            boolean reflected = isReflected(p.value(), respBody);
            store.recordParameter(loc, p.name(), p.value(), endpointKey, endpointPath,
                    reflected, messages);
        }

        // Montoya's parameters() does not decompose a JSON body into keys; do it ourselves.
        if (isJsonRequest(request)) {
            extractJsonKeys(request.bodyToString(), endpointKey, endpointPath, respBody, messages);
        }
    }

    private static ParameterInfo.Location mapLocation(HttpParameterType type) {
        return switch (type) {
            case URL -> ParameterInfo.Location.QUERY;
            case BODY, MULTIPART_ATTRIBUTE -> ParameterInfo.Location.BODY;
            case COOKIE -> ParameterInfo.Location.COOKIE;
            case JSON -> ParameterInfo.Location.JSON;
            default -> null;   // XML and others are ignored for now
        };
    }

    private static boolean isJsonRequest(HttpRequest request) {
        String ct = request.headerValue("Content-Type");
        return ct != null && ct.toLowerCase().contains("json");
    }

    private void extractJsonKeys(String body, String endpointKey, String endpointPath,
                                String respBody, HttpRequestResponse messages) {
        if (body == null || body.isBlank()) {
            return;
        }
        try {
            JsonElement root = JsonParser.parseString(body);
            walkJson("", root, endpointKey, endpointPath, respBody, messages, 0);
        } catch (RuntimeException ignored) {
            // Not valid JSON (or too deep) -> skip; body params already captured above.
        }
    }

    private void walkJson(String prefix, JsonElement el, String endpointKey, String endpointPath,
                          String respBody, HttpRequestResponse messages, int depth) {
        if (depth > 6 || el == null) {
            return;
        }
        if (el.isJsonObject()) {
            for (Map.Entry<String, JsonElement> e : el.getAsJsonObject().entrySet()) {
                String name = prefix.isEmpty() ? e.getKey() : prefix + "." + e.getKey();
                JsonElement v = e.getValue();
                if (v.isJsonPrimitive()) {
                    String val = v.getAsString();
                    store.recordParameter(ParameterInfo.Location.JSON, name, val,
                            endpointKey, endpointPath, isReflected(val, respBody), messages);
                } else {
                    store.recordParameter(ParameterInfo.Location.JSON, name, "",
                            endpointKey, endpointPath, false, messages);
                    walkJson(name, v, endpointKey, endpointPath, respBody, messages, depth + 1);
                }
            }
        } else if (el.isJsonArray() && el.getAsJsonArray().size() > 0) {
            walkJson(prefix + "[]", el.getAsJsonArray().get(0), endpointKey, endpointPath,
                    respBody, messages, depth + 1);
        }
    }

    private static boolean isReflected(String value, String respBody) {
        return value != null && value.length() >= 4 && respBody.contains(value);
    }
}
