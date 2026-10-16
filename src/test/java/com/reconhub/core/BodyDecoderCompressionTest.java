package com.reconhub.core;

import burp.api.montoya.utilities.CompressionType;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * {@code BodyDecoder.compressionTypeFor} -- the pure, headless-testable half of the 0.45.0 compressed-
 * response decoding. The actual inflate uses Montoya's {@code CompressionUtils} (live runtime only), so
 * only the Content-Encoding -> CompressionType mapping is unit-tested here; the inflate itself is a
 * Burp smoke-test item.
 */
class BodyDecoderCompressionTest {

    @Test
    void mapsKnownEncodings() {
        assertEquals(CompressionType.GZIP, BodyDecoder.compressionTypeFor("gzip"));
        assertEquals(CompressionType.GZIP, BodyDecoder.compressionTypeFor("x-gzip"));
        assertEquals(CompressionType.DEFLATE, BodyDecoder.compressionTypeFor("deflate"));
        assertEquals(CompressionType.BROTLI, BodyDecoder.compressionTypeFor("br"));
        assertEquals(CompressionType.BROTLI, BodyDecoder.compressionTypeFor("brotli"));
    }

    @Test
    void isCaseAndWhitespaceInsensitive() {
        assertEquals(CompressionType.GZIP, BodyDecoder.compressionTypeFor("  GZip "));
        assertEquals(CompressionType.BROTLI, BodyDecoder.compressionTypeFor("BR"));
    }

    @Test
    void returnsNullForUnsupportedOrAbsent() {
        assertNull(BodyDecoder.compressionTypeFor(null));
        assertNull(BodyDecoder.compressionTypeFor(""));
        assertNull(BodyDecoder.compressionTypeFor("identity"));
        assertNull(BodyDecoder.compressionTypeFor("compress"));
        assertNull(BodyDecoder.compressionTypeFor("gzip, br"), "multi-value is not a single codec");
    }

    @Test
    void plainBytesStillDecodeWhenNoCompressorWired() {
        // No CompressionUtils injected in a headless test -> decode(byte[], contentType) is unaffected.
        assertEquals("héllo", BodyDecoder.decode("héllo".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                "text/plain; charset=utf-8"));
    }
}
