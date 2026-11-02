package com.reconhub.analysis;

import com.reconhub.model.ParameterInfo;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Value-shape classification (0.56.0): {@code ValueKind} + {@code ParameterClassifier.classesOf}. */
class ValueKindTest {

    @Test
    void kinds() {
        assertEquals(ValueKind.NUMERIC_ID, ValueKind.of("10234"));
        assertEquals(ValueKind.NUMBER, ValueKind.of("2"));
        assertEquals(ValueKind.UUID, ValueKind.of("3f2504e0-4f89-11d3-9a0c-0305e82c3301"));
        assertEquals(ValueKind.EMAIL, ValueKind.of("a.b@mail.example.com"));
        assertEquals(ValueKind.URL, ValueKind.of("https://h.example/x"));
        assertEquals(ValueKind.URL, ValueKind.of("https%3A%2F%2Fh.example%2Fx"));
        assertEquals(ValueKind.URL, ValueKind.of("//h.example/x"));
        assertEquals(ValueKind.PATH, ValueKind.of("/home/mypage"));
        assertEquals(ValueKind.PATH, ValueKind.of("../../etc/passwd"));
        assertEquals(ValueKind.JWT, ValueKind.of("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"));
        assertEquals(ValueKind.SERIALIZED, ValueKind.of("rO0ABXNyABFqYXZh"));
        assertEquals(ValueKind.SERIALIZED, ValueKind.of("a:2:{i:0;s:1:\"x\";}"));
        assertEquals(ValueKind.BASE64, ValueKind.of("aGVsbG8gd29ybGQhIQ+/"));
        assertEquals("", ValueKind.of("hello"));
        assertEquals("", ValueKind.of(""));
        // ParameterInfo's 120-char truncation marker doesn't hide the shape
        assertEquals(ValueKind.URL, ValueKind.of("https://h.example/" + "a".repeat(100) + "…"));
    }

    @Test
    void valueKindAddsItsClassToTheNameClasses() {
        ParameterInfo no = new ParameterInfo(ParameterInfo.Location.QUERY, "articleKey", "k", "/p");
        no.record("884213", false, null);
        assertTrue(ParameterClassifier.classesOf(no).contains("IDOR"), ParameterClassifier.classesOf(no).toString());

        ParameterInfo go = new ParameterInfo(ParameterInfo.Location.QUERY, "x", "k", "/p");
        go.record("https://other.example/", false, null);
        assertEquals("Redirect/SSRF", ParameterClassifier.classesJoinedOf(go));

        ParameterInfo plain = new ParameterInfo(ParameterInfo.Location.QUERY, "q", "k", "/p");
        plain.record("shoes", false, null);
        assertFalse(ParameterClassifier.classesOf(plain).contains("IDOR"));
        assertEquals(ParameterClassifier.classifyCached("q"), ParameterClassifier.classesOf(plain));
    }

    @Test
    void noDuplicateWhenNameAlreadyImpliesTheClass() {
        assertEquals(1, ParameterClassifier.classify("user_id", ValueKind.NUMERIC_ID).stream()
                .filter("IDOR"::equals).count());
    }
}
