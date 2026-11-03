package com.reconhub.analysis;

import com.reconhub.model.Finding;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Display-time how-to-test hints (0.56.0): shipped finding-hints.json + own-hint precedence. */
class FindingHintsTest {

    @Test
    void everyMajorNonJsTypeHasAHint() {
        assertTrue(FindingHints.ruleCount() > 20);
        for (String type : new String[]{"CORS reflected +creds", "CORS wildcard", "CSP unsafe-inline",
                "Cookie no HttpOnly", "Sensitive response cacheable", "Open redirect (candidate)",
                "Reflected param (XSS?)", "Exposed sensitive file", "API spec exposed",
                "GraphQL introspection enabled", "Source map exposed", "Java Stack Trace", "SQL Error",
                "AWS Access Key ID", "JWT", "S3 Bucket URL", "Private IPv4", "Secret in URL", "HTML Comment"}) {
            assertFalse(FindingHints.forType(type).isEmpty(), type);
        }
        assertEquals("", FindingHints.forType("Something unheard of"));
    }

    @Test
    void leadTypesGetTheirOwnHintNotAGenericOne() {
        // 0.57.0: the label after the colon ("password", "kid header") must not reach a generic entry.
        assertTrue(FindingHints.forType("CSRF candidate").contains("CSRF PoC"));
        assertTrue(FindingHints.forType("Sensitive field in response: password").contains("never send"));
        assertTrue(FindingHints.forType("JWT weakness: kid header").contains("jwt_tool"));
        assertTrue(FindingHints.forType("Mass assignment candidate: role").contains("privileged value"));
        assertTrue(FindingHints.forType("Auth flow endpoint: login").contains("enumeration"));
        assertTrue(FindingHints.forType("File upload endpoint").contains("extension"));
    }

    @Test
    void specificEntriesWinOverGenericOnes() {
        assertTrue(FindingHints.forType("CORS reflected +creds").contains("credentials"));
        assertFalse(FindingHints.forType("CORS reflected +creds")
                .equals(FindingHints.forType("CORS wildcard")));
    }

    @Test
    void ownTryHintTakesPrecedence() {
        Finding own = new Finding("AWS Access Key ID", Finding.Severity.HIGH, "AKIA...", "u",
                "ctx  |  Try: my own note", false);
        assertEquals("my own note", FindingHints.of(own));
        assertEquals("", FindingHints.extra(own));

        Finding plain = new Finding("CORS wildcard", Finding.Severity.LOW, "acao=*", "u", "ACAO: *", false);
        assertEquals(FindingHints.forType("CORS wildcard"), FindingHints.of(plain));
        assertEquals(FindingHints.of(plain), FindingHints.extra(plain));
    }
}
