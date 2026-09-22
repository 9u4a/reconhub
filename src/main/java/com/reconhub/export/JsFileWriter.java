package com.reconhub.export;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Writes collected JavaScript bodies to disk, one file per unique content hash. The filename embeds
 * the host, a sanitized path, and the first 8 hex chars of the SHA-256 so files are recognizable and
 * de-duplicated on disk.
 */
public final class JsFileWriter {

    private JsFileWriter() {}

    /**
     * @return the absolute path written (or the existing path if already present).
     * @throws IOException if the directory can't be created or the file can't be written -- the caller
     *         decides how to surface it. (This used to return null on failure, which meant "Save JS to
     *         disk" against an unwritable directory failed silently, forever, for every file.)
     */
    public static Path write(Path directory, String url, String sha256, String body) throws IOException {
        Files.createDirectories(directory);
        String fileName = buildFileName(url, sha256);
        Path target = directory.resolve(fileName);
        if (!Files.exists(target)) {
            Files.write(target, body.getBytes(StandardCharsets.UTF_8));
        }
        return target.toAbsolutePath();
    }

    private static String buildFileName(String url, String sha256) {
        String host = "unknown";
        String path = "root";
        try {
            URI uri = URI.create(url);
            if (uri.getHost() != null) {
                host = uri.getHost();
            }
            if (uri.getPath() != null && !uri.getPath().isBlank()) {
                path = uri.getPath();
            }
        } catch (RuntimeException ignored) {
            // keep defaults
        }
        String base = (host + "_" + path).toLowerCase(Locale.ROOT);
        base = base.replaceAll("[^a-z0-9._-]", "_").replaceAll("_+", "_");
        if (base.length() > 100) {
            base = base.substring(0, 100);
        }
        String shortHash = sha256.length() >= 8 ? sha256.substring(0, 8) : sha256;
        if (!base.endsWith(".js")) {
            base = base + ".js";
        }
        return base.substring(0, base.length() - 3) + "_" + shortHash + ".js";
    }
}
