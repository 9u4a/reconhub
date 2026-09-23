package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;

import java.awt.Desktop;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.net.URI;

/** Small Swing helpers shared across the table panels and dialogs, so "copy to clipboard" and "open
 * in browser" have one implementation instead of several near-identical, independently-drifted
 * copies (one of which logged failures and two of which silently swallowed them). */
final class UiUtil {
    private UiUtil() {
    }

    /** Copies {@code s} to the system clipboard. No-op for null. */
    static void copyToClipboard(String s) {
        if (s != null) {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(s), null);
        }
    }

    /** Opens {@code url} in the OS default browser, if supported. Failures are logged, never thrown.
     * {@code Desktop.browse} declares {@code IOException}, so this catches the broader {@code
     * Exception} (matching the pre-existing call sites this replaces). */
    static void openInBrowser(MontoyaApi api, String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
            }
        } catch (Exception e) {
            if (api != null) {
                api.logging().logToError("ReconHub: open in browser failed for " + url + ": " + e);
            }
        }
    }
}
