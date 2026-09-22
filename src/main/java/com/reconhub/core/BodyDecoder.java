package com.reconhub.core;

import burp.api.montoya.http.message.HttpMessage;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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
 */
public final class BodyDecoder {
    private BodyDecoder() {
    }

    private static final Pattern CHARSET_PARAM =
            Pattern.compile("(?i)charset\\s*=\\s*\"?([A-Za-z0-9_\\-:.]+)");

    /** Decodes {@code message}'s body using its own {@code Content-Type} header. Never null. */
    public static String decode(HttpMessage message) {
        if (message == null) {
            return "";
        }
        return decode(message.body().getBytes(), message.headerValue("Content-Type"));
    }

    /** Decodes raw body bytes using {@code contentType}'s charset param (default UTF-8). Never null. */
    public static String decode(byte[] bytes, String contentType) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        return new String(bytes, charsetOf(contentType));
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
