package com.reconhub.ui;

import com.reconhub.active.BruteforceEngine;
import com.reconhub.active.BruteforceJob;
import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.model.Endpoint;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.Component;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Shared "run known-path bruteforce on this host" action, invoked from a host/endpoint/parameter
 * row's right-click menu. There is no separate master on/off switch — this confirmation dialog (with
 * the target address in an editable field, defaulted from the row but changeable before running) is
 * the sole, mandatory gate every single run goes through. Never a silent run.
 */
public final class RunBruteforceAction {

    private RunBruteforceAction() {}

    /**
     * @param suggestedTarget a bare host ({@code "example.com"}) or a full origin
     *                        ({@code "https://example.com:8443"}); when bare, the scheme defaults to
     *                        one already observed for that host in {@code store} (falling back to
     *                        https only if the host has never been seen). Passing the wrong scheme
     *                        here — e.g. https against a plain-HTTP dev server — makes every request
     *                        fail its TLS handshake, showing up as status 0 for every probe including
     *                        the baseline; the editable field lets the user fix this before running.
     */
    public static void run(Component owner, BruteforceEngine engine, Settings settings,
                           DataStore store, String suggestedTarget) {
        if (suggestedTarget == null || suggestedTarget.isBlank()) {
            return;
        }

        String defaultUrl = suggestedTarget.contains("://")
                ? suggestedTarget
                : inferScheme(store, suggestedTarget) + "://" + suggestedTarget;
        JTextField targetField = new JTextField(defaultUrl, 32);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        panel.add(left(new JLabel("Target (edit if needed, e.g. wrong scheme/port/subdomain):")));
        targetField.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(targetField);
        panel.add(Box.createVerticalStrut(8));
        panel.add(left(new JLabel("Wordlist size: " + engine.getWordlist().size() + " paths")));
        panel.add(left(new JLabel("Estimated requests: ~" + engine.estimateRequests())));
        panel.add(left(new JLabel("Throttle: " + settings.getBruteforceDelayMs() + " ms delay, concurrency "
                + settings.getBruteforceConcurrency() + ", budget "
                + settings.getBruteforceMaxRequestsPerHost() + "/host")));
        panel.add(Box.createVerticalStrut(6));
        panel.add(left(new JLabel("Requests will be sent to the target. Proceed?")));

        int ok = JOptionPane.showConfirmDialog(owner, panel, "ReconHub — confirm active bruteforce",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) {
            return;
        }
        String target = targetField.getText().trim();
        if (target.isEmpty()) {
            return;
        }
        BruteforceJob job = engine.submit(target);
        if (job == null) {
            JOptionPane.showMessageDialog(owner,
                    "Refused — target could not be parsed, or is out of scope "
                            + "(check Settings → Scope).",
                    "ReconHub", JOptionPane.WARNING_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(owner,
                    "Started against " + job.getHost() + ". Track progress in the Bruteforce tab.",
                    "ReconHub", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * The scheme already observed for {@code host} in captured traffic ({@code "http"} or
     * {@code "https"}), or {@code "https"} if the host has no recorded endpoint yet. Prevents
     * defaulting to https against a host only ever seen over plain http (or vice versa), which would
     * make every probe fail its TLS handshake.
     *
     * <p>Delegates to {@link #schemesByHost} so the two never drift apart. Fine for the single-host
     * call sites this was written for (a right-click action on one host, once per click) -- each such
     * call still scans {@code store.snapshotEndpoints()} once, same as before 0.41.0. A caller that
     * needs the scheme for <em>many</em> hosts at once should call {@link #schemesByHost} directly
     * instead of calling this in a loop (that used to be an O(hosts &times; endpoints) trap --
     * see {@code SettingsPanel.doRemoveOutOfScope}).
     */
    static String inferScheme(DataStore store, String host) {   // package-private for headless testing
        if (store == null || host == null) {
            return "https";
        }
        return schemesByHost(store).getOrDefault(host.toLowerCase(Locale.ROOT), "https");
    }

    /**
     * The scheme observed for every host that has at least one recorded endpoint, computed in a single
     * pass over {@link DataStore#snapshotEndpoints()} -- for callers that need this for many hosts at
     * once (unlike {@link #inferScheme}, which is for one host per call). Keyed by lower-cased host,
     * matching {@link #inferScheme}'s case-insensitive comparison. When a host has endpoints recorded
     * under both schemes, the first one encountered in {@code snapshotEndpoints()}'s (deterministic)
     * order wins -- the same "first match" semantics {@link #inferScheme}'s linear scan had.
     */
    static Map<String, String> schemesByHost(DataStore store) {   // package-private for headless testing
        Map<String, String> schemes = new HashMap<>();
        if (store == null) {
            return schemes;
        }
        for (Endpoint e : store.snapshotEndpoints()) {
            String host = e.getHost();
            String url = e.getNormalizedUrl();
            if (host == null || url == null) {
                continue;
            }
            String scheme = url.startsWith("http://") ? "http" : url.startsWith("https://") ? "https" : null;
            if (scheme != null) {
                schemes.putIfAbsent(host.toLowerCase(Locale.ROOT), scheme);
            }
        }
        return schemes;
    }

    private static Component left(Component c) {
        if (c instanceof javax.swing.JComponent jc) {
            jc.setAlignmentX(Component.LEFT_ALIGNMENT);
        }
        return c;
    }
}
