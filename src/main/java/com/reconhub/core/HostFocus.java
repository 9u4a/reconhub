package com.reconhub.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/**
 * The session-wide "show only this host" selection (0.54.0) shared by the Endpoints / Parameters /
 * Findings tabs. {@code null} = all hosts (no focus).
 *
 * <p>Applied at the row-<i>source</i> level (each panel's {@code supplyRows()}, via {@link Scoped}),
 * not as a {@code rowIncluded} quick filter -- so the row-count label, the checklist column filters,
 * Findings' category counts, body search and CSV export all follow the focused host automatically,
 * and everything downstream of {@code supplyRows()} works on fewer rows, not more.
 *
 * <p>Host match is exact (case-insensitive) -- unlike the search box, focusing {@code a.com} never
 * pulls in {@code a.com.evil.net}. Montoya-free, headless-tested ({@code HostFocusTest}).
 */
public final class HostFocus {

    private volatile String host;
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    /** @return the focused host, or {@code null} when every host is shown. */
    public String get() {
        return host;
    }

    public boolean isActive() {
        return host != null;
    }

    /** Sets the focus ({@code null}/blank clears it) and notifies listeners on the caller's thread --
     * called from the EDT only (UI actions). No-op (no notification) when the value doesn't change. */
    public void set(String newHost) {
        String h = newHost == null || newHost.isBlank() ? null : newHost.trim();
        String cur = host;
        if (h == null ? cur == null : h.equalsIgnoreCase(cur)) {
            return;
        }
        host = h;
        for (Runnable l : listeners) {
            l.run();
        }
    }

    public void clear() {
        set(null);
    }

    public void addListener(Runnable l) {
        listeners.add(l);
    }

    public void removeListener(Runnable l) {
        listeners.remove(l);
    }

    /** @return true when {@code rowHost} is shown under {@code focus} ({@code null} focus = everything). */
    public static boolean matches(String focus, String rowHost) {
        return focus == null || focus.equalsIgnoreCase(rowHost);
    }

    /** The rows of {@code source} whose host matches {@code focus} -- {@code source} itself when there
     * is no focus. Never mutates {@code source}; the result is unmodifiable. */
    public static <T> List<T> filter(List<T> source, String focus, Function<T, String> hostOf) {
        if (focus == null) {
            return source;
        }
        List<T> out = new ArrayList<>();
        for (T row : source) {
            if (matches(focus, hostOf.apply(row))) {
                out.add(row);
            }
        }
        return Collections.unmodifiableList(out);
    }

    /**
     * Per-panel memo of {@link #filter}: {@code DataStore.snapshotX()} hands back the <i>same</i> list
     * instance until its collection's key set changes, and a row's host never changes, so an identity
     * compare on the source list + an equal focus means the previous result is still exact. That makes
     * the common 300ms refresh tick (nothing new for this collection) O(1) instead of O(n). EDT-only,
     * like the {@code supplyRows()} that calls it.
     */
    public static final class Scoped<T> {
        private final Function<T, String> hostOf;
        private List<T> lastSource;
        private String lastFocus;
        private List<T> lastResult;

        public Scoped(Function<T, String> hostOf) {
            this.hostOf = hostOf;
        }

        public List<T> apply(List<T> source, String focus) {
            if (focus == null) {
                lastSource = null;   // don't pin an old snapshot while unfocused
                lastResult = null;
                lastFocus = null;
                return source;
            }
            if (source == lastSource && focus.equalsIgnoreCase(lastFocus)) {
                return lastResult;
            }
            lastResult = filter(source, focus, hostOf);
            lastSource = source;
            lastFocus = focus;
            return lastResult;
        }
    }
}
