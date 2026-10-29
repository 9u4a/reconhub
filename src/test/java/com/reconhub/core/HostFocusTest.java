package com.reconhub.core;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** {@code HostFocus} -- the 0.54.0 "show only this host" selection. Pure logic, headless. */
class HostFocusTest {

    private static final Function<String, String> HOST_OF = s -> s.substring(0, s.indexOf('/'));
    private static final List<String> ROWS =
            List.of("a.com/x", "a.com.evil.net/y", "b.com/z", "A.COM/w", "/relative");

    @Test
    void noFocusReturnsTheSourceListItself() {
        assertSame(ROWS, HostFocus.filter(ROWS, null, HOST_OF));
    }

    @Test
    void matchIsExactAndCaseInsensitiveNotSubstring() {
        assertEquals(List.of("a.com/x", "A.COM/w"), HostFocus.filter(ROWS, "a.com", HOST_OF));
    }

    @Test
    void unknownHostYieldsEmpty() {
        assertTrue(HostFocus.filter(ROWS, "c.com", HOST_OF).isEmpty());
    }

    @Test
    void setNormalizesBlankToNullAndOnlyNotifiesOnChange() {
        HostFocus f = new HostFocus();
        AtomicInteger calls = new AtomicInteger();
        f.addListener(calls::incrementAndGet);

        f.set("  ");
        assertNull(f.get());
        assertEquals(0, calls.get());

        f.set("a.com");
        assertTrue(f.isActive());
        f.set("A.COM");   // same host, different case -> no-op
        assertEquals("a.com", f.get());
        assertEquals(1, calls.get());

        f.clear();
        assertFalse(f.isActive());
        assertEquals(2, calls.get());
    }

    @Test
    void scopedReusesResultWhileSourceIdentityAndFocusAreUnchanged() {
        HostFocus.Scoped<String> s = new HostFocus.Scoped<>(HOST_OF);
        List<String> first = s.apply(ROWS, "a.com");
        assertSame(first, s.apply(ROWS, "a.com"));
        assertSame(first, s.apply(ROWS, "A.com"));
    }

    @Test
    void scopedRecomputesOnNewSourceOrNewFocus() {
        HostFocus.Scoped<String> s = new HostFocus.Scoped<>(HOST_OF);
        List<String> first = s.apply(ROWS, "a.com");

        List<String> grown = new java.util.ArrayList<>(ROWS);
        grown.add("a.com/new");
        List<String> second = s.apply(grown, "a.com");
        assertNotSame(first, second);
        assertEquals(3, second.size());

        assertEquals(List.of("b.com/z"), s.apply(grown, "b.com"));
    }

    @Test
    void scopedWithNoFocusPassesThrough() {
        HostFocus.Scoped<String> s = new HostFocus.Scoped<>(HOST_OF);
        s.apply(ROWS, "a.com");
        assertSame(ROWS, s.apply(ROWS, null));
    }
}
