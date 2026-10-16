package com.reconhub.core;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.utilities.CompressionType;
import burp.api.montoya.utilities.CompressionUtils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Decodes an HTTP request/response body to text using its own {@code Content-Type} charset
 * (default UTF-8) — unlike {@link HttpMessage#bodyToString()}, which byte-maps each byte straight
 * to one char (an ISO-8859-1-style 1:1 mapping) and mangles any multibyte text (Korean, Japanese,
 * Chinese, most non-ASCII scripts) into mojibake. Use this instead of {@code bodyToString()}
 * anywhere the decoded text is analyzed for content that may end up shown to the user — Findings
 * evidence, extracted parameter values, JS/API-spec analysis, tech-signature matching, "Copy as
 * curl", etc. Byte-mapped decoding is still fine where the text is only re-encoded back to the
 * exact same bytes and never read as characters (there is currently no such use in this codebase).
 * {@link #encode} is the inverse, for the rare case of feeding edited/derived text back into a
 * Montoya {@code HttpResponse} (e.g. a beautified body) — using {@code HttpResponse.withBody(String)}
 * directly would re-introduce the same mojibake bug on the encode side.
 */
public final class BodyDecoder {
    private BodyDecoder() {
    }

    private static final Pattern CHARSET_PARAM =
            Pattern.compile("(?i)charset\\s*=\\s*\"?([A-Za-z0-9_\\-:.]+)");

    // Burp's own compression codec (gzip/deflate/brotli), injected at extension init via
    // setCompressionUtils. Null in headless tests -> decompression is simply skipped (raw bytes used).
    private static volatile CompressionUtils compressor;
    private static volatile Consumer<String> logger = msg -> { };
    private static final AtomicLong decompressFailures = new AtomicLong();

    /** Wires Burp's {@code api.utilities().compressionUtils()} so {@link #decode(HttpMessage)} can
     * transparently inflate {@code Content-Encoding} bodies. */
    public static void setCompressionUtils(CompressionUtils utils) {
        compressor = utils;
    }

    /** Wires a logger (e.g. {@code api.logging()::logToError}) for the rate-limited decompress-failure
     * notice; no-op until set (headless). */
    public static void setLogger(Consumer<String> l) {
        logger = l == null ? msg -> { } : l;
    }

    /** Decodes {@code message}'s body using its own {@code Content-Type} header, transparently inflating
     * a {@code Content-Encoding: gzip/deflate/br} body first (so analysis/search sees real text, not
     * compressed bytes). Never null. */
    public static String decode(HttpMessage message) {
        if (message == null) {
            return "";
        }
        byte[] bytes = decompressIfNeeded(message.body(), message.headerValue("Content-Encoding"));
        return decode(bytes, message.headerValue("Content-Type"));
    }

    /** Maps a {@code Content-Encoding} header value to Burp's {@link CompressionType}, or null when it
     * isn't a (single) supported compression ({@code identity}, empty, multi-value, or unknown). Pure
     * and case-insensitive -- the headless-testable half of the decompression path. */
    static CompressionType compressionTypeFor(String encoding) {
        if (encoding == null) {
            return null;
        }
        switch (encoding.trim().toLowerCase(Locale.ROOT)) {
            case "gzip":
            case "x-gzip":
                return CompressionType.GZIP;
            case "deflate":
                return CompressionType.DEFLATE;
            case "br":
            case "brotli":
                return CompressionType.BROTLI;
            default:
                return null;   // identity, chunked-only, "gzip, br" multi-value, unknown -> leave as-is
        }
    }

    /** Returns {@code body} inflated per {@code encoding} when applicable, else its raw bytes. Falls
     * back to the raw bytes on any failure (incl. a body Burp already inflated but whose header still
     * says gzip -- caught by the magic-byte check or the decompress throw). */
    private static byte[] decompressIfNeeded(ByteArray body, String encoding) {
        byte[] raw = body.getBytes();
        CompressionUtils c = compressor;
        CompressionType type = compressionTypeFor(encoding);
        if (c == null || type == null || raw.length == 0) {
            return raw;
        }
        // GZIP has a fixed 2-byte magic (0x1f 0x8b); if it's absent the body isn't really gzipped
        // (most often Burp already unpacked it and left the header), so don't even attempt it.
        if (type == CompressionType.GZIP
                && !(raw.length >= 2 && (raw[0] & 0xff) == 0x1f && (raw[1] & 0xff) == 0x8b)) {
            return raw;
        }
        try {
            return c.decompress(body, type).getBytes();
        } catch (RuntimeException e) {
            long n = decompressFailures.getAndIncrement();
            if (n == 0 || n % 100 == 0) {
                logger.accept("ReconHub: failed to decompress a " + type + " body "
                        + "(using it as-is): " + e);
            }
            return raw;
        }
    }

    /** Decodes raw body bytes using {@code contentType}'s charset param (default UTF-8). Never null. */
    public static String decode(byte[] bytes, String contentType) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        return new String(bytes, charsetOf(contentType));
    }

    /** Inverse of {@link #decode}: encodes {@code text} using {@code contentType}'s charset param
     * (default UTF-8). Never null. */
    public static byte[] encode(String text, String contentType) {
        if (text == null || text.isEmpty()) {
            return new byte[0];
        }
        return text.getBytes(charsetOf(contentType));
    }

    private static Charset charsetOf(String contentType) {
        if (contentType != null) {
            Matcher m = CHARSET_PARAM.matcher(contentType);
            if (m.find()) {
                try {
                    return Charset.forName(m.group(1).trim());
                } catch (RuntimeException ignored) {
                    // unknown/unsupported charset name -> fall through to UTF-8
                }
            }
        }
        return StandardCharsets.UTF_8;
    }
}
