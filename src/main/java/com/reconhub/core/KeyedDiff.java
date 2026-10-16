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
 * <p>v1 ({@link #compute(List, List, Function)}) answered Added/Removed only. {@link #compute(List,
 * List, Function, Function)} (0.45.0) adds "Changed" via a caller-supplied {@code signatureOf} -- the
 * caller decides what counts as a meaningful change per model type (an Endpoint's status/params, a
 * Tech host's technologies), keeping this class type-agnostic.
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

    /** Added/removed (as {@link Diff}) plus {@code changed}: keys present in both lists whose {@code
     *  signatureOf} differs. {@code changed} holds the NEW-side rows (current content). */
    public record Diff3<T>(List<T> added, List<T> removed, List<T> changed) {}

    /**
     * Like {@link #compute(List, List, Function)} but also classifies "changed" rows -- a key present in
     * both lists whose {@code signatureOf} (caller's notion of meaningful content) differs between the
     * old and new row. A changed key is reported only in {@code changed} (not also added/removed), and
     * the returned row is the NEW one so the UI shows the current value. Pass {@code signatureOf =
     * keyOf} to make "changed" impossible (e.g. a content-hash key like {@code JsAsset}'s sha256).
     */
    public static <T> Diff3<T> compute(List<T> oldRows, List<T> newRows,
                                       Function<T, String> keyOf, Function<T, String> signatureOf) {
        Map<String, T> oldByKey = index(oldRows, keyOf);
        Map<String, T> newByKey = index(newRows, keyOf);

        List<T> added = new ArrayList<>();
        List<T> changed = new ArrayList<>();
        for (Map.Entry<String, T> e : newByKey.entrySet()) {
            T oldRow = oldByKey.get(e.getKey());
            if (oldRow == null) {
                added.add(e.getValue());
            } else if (!sig(signatureOf, oldRow).equals(sig(signatureOf, e.getValue()))) {
                changed.add(e.getValue());   // NEW-side row = current content
            }
        }
        List<T> removed = new ArrayList<>();
        for (Map.Entry<String, T> e : oldByKey.entrySet()) {
            if (!newByKey.containsKey(e.getKey())) {
                removed.add(e.getValue());
            }
        }
        return new Diff3<>(added, removed, changed);
    }

    private static <T> String sig(Function<T, String> signatureOf, T row) {
        String s = signatureOf.apply(row);
        return s == null ? "" : s;
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
