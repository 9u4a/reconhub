package com.reconhub.core;

import burp.api.montoya.MontoyaApi;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * User-authored bookmarks/notes on any row, keyed by the row's own {@code key()} string (every
 * model class -- {@code Endpoint}/{@code ParameterInfo}/{@code Finding}/{@code JsAsset}/{@code
 * TechInfo} -- already has one, and {@link DataStore} already uses it as the map key, so one
 * string-keyed map here covers all five row types without touching any model class). Deliberately
 * NOT a field on the model classes (the {@code Finding.Triage} pattern) and NOT stored inside {@link
 * DataStore}: bookmarks are user-authored data, and {@link DataStore#clear()} wiping them along with
 * scraped traffic data would be a real data-loss bug. Persisted the same way as {@link Settings} --
 * the whole map as one Gson JSON blob under one Montoya extension-preference key.
 */
public final class Bookmarks {

    /** @param note empty string, never null, when there is no note. */
    public record Entry(boolean bookmarked, String note) {}

    private static final Entry EMPTY = new Entry(false, "");
    private static final String PREF_KEY = "reconhub.bookmarks.v1";

    private final Map<String, Entry> byKey = new ConcurrentHashMap<>();

    public boolean isBookmarked(String key) {
        return key != null && byKey.getOrDefault(key, EMPTY).bookmarked();
    }

    public String noteFor(String key) {
        return key == null ? "" : byKey.getOrDefault(key, EMPTY).note();
    }

    public void setBookmarked(String key, boolean bookmarked) {
        if (key == null) {
            return;
        }
        put(key, bookmarked, noteFor(key));
    }

    public void setNote(String key, String text) {
        if (key == null) {
            return;
        }
        put(key, isBookmarked(key), text == null ? "" : text);
    }

    private void put(String key, boolean bookmarked, String note) {
        if (!bookmarked && note.isEmpty()) {
            byKey.remove(key);   // don't let the map grow with empty entries
        } else {
            byKey.put(key, new Entry(bookmarked, note));
        }
    }

    /** Full snapshot for {@code export.StateSerializer}. */
    public Map<String, Entry> snapshotAll() {
        return new HashMap<>(byKey);
    }

    /** Restores one entry from an imported state file ({@code export.StateSerializer}). */
    public void restore(String key, Entry e) {
        if (key != null && e != null && (e.bookmarked() || !e.note().isEmpty())) {
            byKey.put(key, e);
        }
    }

    // ---- Persistence (Montoya extension preferences) ---------------------
    // Same "whole object as one Gson JSON blob under one preference key" pattern as core.Settings
    // and analysis.UserRuleStore.

    public void save(MontoyaApi api) {
        try {
            api.persistence().preferences().setString(PREF_KEY, new Gson().toJson(byKey));
        } catch (RuntimeException e) {
            api.logging().logToError("ReconHub: failed to save bookmarks: " + e);
        }
    }

    public static Bookmarks load(MontoyaApi api) {
        Bookmarks b = new Bookmarks();
        try {
            String json = api.persistence().preferences().getString(PREF_KEY);
            if (json != null && !json.isBlank()) {
                Type type = new TypeToken<Map<String, Entry>>() {}.getType();
                Map<String, Entry> loaded = new Gson().fromJson(json, type);
                if (loaded != null) {
                    for (Map.Entry<String, Entry> e : loaded.entrySet()) {
                        b.restore(e.getKey(), e.getValue());
                    }
                }
            }
        } catch (RuntimeException e) {
            api.logging().logToError("ReconHub: failed to load bookmarks, starting empty: " + e);
        }
        return b;
    }
}
