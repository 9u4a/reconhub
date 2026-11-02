package com.reconhub.analysis;

import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Hidden-parameter extraction (0.56.0): {@code JsAnalyzer.paramNames} / {@code isInterestingParam}
 * against the shipped js-params.json. Pure logic, headless. */
class JsParamRulesTest {

    private static final PatternRegistry REG = PatternRegistry.load();

    private static Set<String> names(String body) {
        return JsAnalyzer.paramNames(body, REG.jsParamRules());
    }

    @Test
    void extractsTheCommonShapes() {
        assertTrue(names("new URLSearchParams(location.search).get(\"debug\")").contains("debug"));
        assertTrue(names("const p=x.searchParams;p.get(\"a\");params.has(\"draft\")").contains("draft"));
        assertTrue(names("t.searchParams.set('returnUrl', x)").contains("returnUrl"));
        assertTrue(names("fd.append(\"isAdmin\", true)").contains("isAdmin"));
        assertTrue(names("fetch(\"/api/list?page=1&preview=true\")").containsAll(Set.of("page", "preview")));
        assertTrue(names("axios.get(u,{params:{role:r}})").contains("role"));
        assertTrue(names("$.ajax({url:u,data:{ \"userId\": 1}})").contains("userId"));
    }

    @Test
    void ignoresCodeThatOnlyLooksLikeIt() {
        Set<String> n = names("a&&b=c; x?y=1:2; h.set(\"Content-Type\", v); if(a&b===c){}");
        assertFalse(n.contains("b"), n.toString());
        assertFalse(n.contains("y"), n.toString());
        assertFalse(n.contains("Content-Type"), n.toString());
    }

    @Test
    void capsNamesPerBody() {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 500; i++) {
            b.append("fd.append(\"p").append(i).append("\", 1);");
        }
        assertEquals(JsAnalyzer.MAX_PARAMS_PER_BODY, names(b.toString()).size());
    }

    @Test
    void onlyActionableNamesAreInteresting() {
        Pattern p = REG.jsParamInteresting();
        for (String n : new String[]{"debug", "isAdmin", "is_admin", "role", "redirect_uri", "callback",
                "userId", "skipVerification", "include_deleted"}) {
            assertTrue(JsAnalyzer.isInterestingParam(n, p), n);
        }
        for (String n : new String[]{"page", "q", "lang", "utm_source", "debugger", "roles2"}) {
            assertFalse(JsAnalyzer.isInterestingParam(n, p), n);
        }
        assertEquals(FindingTaxonomy.Category.AUTH,
                FindingTaxonomy.categoryOf(JsAnalyzer.HIDDEN_PARAM_PREFIX + "redirect"));
    }
}
