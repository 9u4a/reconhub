package com.reconhub.analysis;

import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

/** {@code JsRisk} (0.55.0) -- per-JS-file score + identity memo. Pure logic, headless. */
class JsRiskTest {

    private static Finding f(String type, Finding.Severity sev, String loc) {
        return new Finding(type, sev, type + "-m", loc, "ev", false);
    }

    @Test
    void scoreIsSeverityWeightedWithFlowBonus() {
        List<Finding> fs = List.of(
                f("DOM XSS: URL fragment -> innerHTML", Finding.Severity.HIGH, "a.js"),
                f("CryptoJS AES key", Finding.Severity.MEDIUM, "a.js"),
                f("Sensitive route in JS: internal/debug", Finding.Severity.LOW, "a.js"),
                f("Comment", Finding.Severity.INFO, "a.js"),
                f("eval() sink", Finding.Severity.HIGH, "b.js"));
        Map<String, JsRisk.Stat> m = JsRisk.byLocation(fs);
        assertEquals(new JsRisk.Stat(4, 10 + JsRisk.FLOW_BONUS + 4 + 1), m.get("a.js"));
        assertEquals(new JsRisk.Stat(1, 10), m.get("b.js"));
        assertEquals(new JsRisk.Stat(0, 0), JsRisk.of(m, "missing.js"));
        assertEquals(new JsRisk.Stat(0, 0), JsRisk.of(m, null));
    }

    @Test
    void memoReusesMapUntilSourceListChanges() {
        JsRisk.Memo memo = new JsRisk.Memo();
        List<Finding> a = new ArrayList<>(List.of(f("x", Finding.Severity.LOW, "a.js")));
        Map<String, JsRisk.Stat> first = memo.get(a);
        assertSame(first, memo.get(a));
        List<Finding> b = new ArrayList<>(a);
        b.add(f("y", Finding.Severity.HIGH, "a.js"));
        Map<String, JsRisk.Stat> second = memo.get(b);
        assertNotSame(first, second);
        assertEquals(11, second.get("a.js").score());
    }
}
