package com.reconhub.core;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.ToIntFunction;

/**
 * A cache bounded by total <b>weight</b> (e.g. character count of cached strings), not entry count,
 * evicting only as many <b>least-recently-used</b> entries as needed to get back under budget -- not
 * the whole cache. Extracted from {@code ui.AbstractTablePanel}'s body-search cache (0.43.2), which
 * used to clear itself entirely on every overflow: with "Body" search on by default and a cap far
 * smaller than any realistic accumulated dataset, that meant the *entire* working set was evicted and
 * every row's request/response re-decoded from scratch on nearly every search once enough data had
 * built up -- decoding runs synchronously on the EDT (Swing's `RowFilter` is inherently synchronous),
 * so that repeated full-redecode was exactly the "search gets laggy once data accumulates" symptom this
 * fixes. {@link LinkedHashMap} with {@code accessOrder=true} gives LRU iteration order for free from a
 * plain {@code get}/{@code put} -- no separate bookkeeping needed.
 *
 * <p>Backed by a plain {@code LinkedHashMap}, so keys are compared by {@code equals()}/{@code
 * hashCode()} same as any {@code Map} -- for a key type with no override (identity semantics, as every
 * {@code model.*} row class deliberately has, see the 0.32.1 CLAUDE.md note), this behaves exactly like
 * an {@code IdentityHashMap} would, just with recency tracking added.
 */
public final class BoundedCache<K, V> {

    private final Map<K, V> map = new LinkedHashMap<>(16, 0.75f, true);
    private final int maxWeight;
    private final ToIntFunction<V> weigher;
    private int currentWeight;

    public BoundedCache(int maxWeight, ToIntFunction<V> weigher) {
        this.maxWeight = maxWeight;
        this.weigher = weigher;
    }

    /** A hit also marks {@code key} as most-recently-used. */
    public V get(K key) {
        return map.get(key);
    }

    public int size() {
        return map.size();
    }

    /**
     * Inserts {@code key}/{@code value}, then evicts least-recently-used entries (not necessarily
     * {@code key} itself, which was just inserted and so is most-recently-used) until back under
     * {@code maxWeight} -- always leaves at least one entry, even if it alone exceeds the budget (a
     * single oversized value temporarily over budget is fine; evicting everything including itself
     * would defeat the point of inserting it).
     */
    public void put(K key, V value) {
        map.put(key, value);
        currentWeight += weigher.applyAsInt(value);
        var it = map.entrySet().iterator();
        while (currentWeight > maxWeight && map.size() > 1 && it.hasNext()) {
            Map.Entry<K, V> eldest = it.next();
            currentWeight -= weigher.applyAsInt(eldest.getValue());
            it.remove();
        }
    }

    /** Drops every entry whose key isn't in {@code keep} (identity-or-equals, matching the backing
     * map's own key semantics) -- e.g. after rows were removed from the table this cache is for. */
    public void retainKeys(Collection<K> keep) {
        Map<K, V> kept = new LinkedHashMap<>(16, 0.75f, true);
        int weight = 0;
        for (K k : keep) {
            V v = map.get(k);
            if (v != null) {
                kept.put(k, v);
                weight += weigher.applyAsInt(v);
            }
        }
        map.clear();
        map.putAll(kept);
        currentWeight = weight;
    }
}
