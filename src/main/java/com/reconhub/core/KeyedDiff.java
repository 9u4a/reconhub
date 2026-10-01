package com.reconhub.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Generic added/removed diff between two row lists, keyed by each row's own {@code key()} (every
 * {@code model.*} class already has one). Used by {@code ui.SnapshotDiffPanel} (0.43.0) to compare a
 * loaded State export against the live {@link DataStore} -- deliberately not {@code DataStore}-specific
 * (just operates on two {@code List<T>}s + a key function) so it's trivially headless-testable without
 * needing a real {@code DataStore} at all.
 *
 * <p>"Changed" (same key, different content) is out of scope -- what counts as a meaningful change
 * differs per model type (a status code changing matters for an Endpoint, a triage change doesn't mean
 * anything for a freshly-loaded comparison file), so v1 only answers "is this key present now that
 * wasn't before" / "was this key present before that isn't now".
 */
public final class KeyedDiff {

    private KeyedDiff() {}

    /** @param added rows whose key is in {@code newRows} but not {@code oldRows} (present now, wasn't
     *               before).
     *  @param removed rows whose key is in {@code oldRows} but not {@code newRows} (was there before,
     *                 gone now) -- these come from {@code oldRows}, since that's the only list that
     *                 still has them. */
    public record Diff<T>(List<T> added, List<T> removed) {}

    public static <T> Diff<T> compute(List<T> oldRows, List<T> newRows, Function<T, String> keyOf) {
        Map<String, T> oldByKey = index(oldRows, keyOf);
        Map<String, T> newByKey = index(newRows, keyOf);

        List<T> added = new ArrayList<>();
        for (Map.Entry<String, T> e : newByKey.entrySet()) {
            if (!oldByKey.containsKey(e.getKey())) {
                added.add(e.getValue());
            }
        }
        List<T> removed = new ArrayList<>();
        for (Map.Entry<String, T> e : oldByKey.entrySet()) {
            if (!newByKey.containsKey(e.getKey())) {
                removed.add(e.getValue());
            }
        }
        return new Diff<>(added, removed);
    }

    private static <T> Map<String, T> index(List<T> rows, Function<T, String> keyOf) {
        // LinkedHashMap: preserves input order in added/removed, which matters for a deterministic UI
        // (and deterministic test assertions) -- not just correctness.
        Map<String, T> m = new LinkedHashMap<>();
        for (T row : rows) {
            String k = keyOf.apply(row);
            if (k != null) {
                m.put(k, row);
            }
        }
        return m;
    }
}
