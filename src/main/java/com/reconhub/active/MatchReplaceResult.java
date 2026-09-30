package com.reconhub.active;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * One outcome of a Match & Replace bulk send -- one row of {@code ui.MatchReplacePanel}'s results
 * table. {@code error} is set instead of a status/length when the request couldn't be built or sent at
 * all (header absent with "add if missing" off, out of scope, send failure) -- these are recorded, not
 * silently skipped, so the user can see exactly how many of their selection didn't go out and why.
 * {@code messages} carries the actual sent request + response for the detail viewer when the send
 * succeeded; {@code null} when it never went out.
 */
public final class MatchReplaceResult {

    private final String host;
    private final String path;
    private final String method;
    private final int status;          // 0 when not sent / no response
    private final int lengthBytes;     // 0 when not sent / no response
    private final long timestamp;
    private final String error;        // null on a normal send
    private final HttpRequestResponse messages;   // null when never sent

    public MatchReplaceResult(String host, String path, String method, int status, int lengthBytes,
                              long timestamp, String error, HttpRequestResponse messages) {
        this.host = host;
        this.path = path;
        this.method = method;
        this.status = status;
        this.lengthBytes = lengthBytes;
        this.timestamp = timestamp;
        this.error = error;
        this.messages = messages;
    }

    /** A result for an endpoint the rule couldn't be applied to / that failed to send -- no
     * status/length/messages, just the reason. */
    public static MatchReplaceResult failed(String host, String path, String method, String error) {
        return new MatchReplaceResult(host, path, method, 0, 0, System.currentTimeMillis(), error, null);
    }

    /** A result for a request that was actually sent (response may still be null -- a timed-out /
     * connection-refused send still counts as "sent", just with no response to show). */
    public static MatchReplaceResult sent(String host, String path, String method,
                                          HttpRequestResponse messages) {
        int status = messages != null && messages.response() != null
                ? messages.response().statusCode() : 0;
        int length = messages != null && messages.response() != null
                ? messages.response().toByteArray().length() : 0;
        return new MatchReplaceResult(host, path, method, status, length,
                System.currentTimeMillis(), null, messages);
    }

    public String getHost() { return host; }
    public String getPath() { return path; }
    public String getMethod() { return method; }
    public int getStatus() { return status; }
    public int getLengthBytes() { return lengthBytes; }
    public long getTimestamp() { return timestamp; }
    public String getError() { return error; }
    public HttpRequestResponse getMessages() { return messages; }

    /** Stable identity for {@code AbstractTablePanel}'s selection-preserving refresh -- results are
     * append-only within one job, so host+path+timestamp is unique enough (two results for the same
     * endpoint in the same run always differ in timestamp). */
    public String key() {
        return host + "|" + path + "|" + timestamp;
    }
}
