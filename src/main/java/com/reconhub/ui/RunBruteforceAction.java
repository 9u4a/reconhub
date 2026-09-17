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
     */
    static String inferScheme(DataStore store, String host) {   // package-private for headless testing
        if (store != null && host != null) {
            for (Endpoint e : store.snapshotEndpoints()) {
                if (host.equalsIgnoreCase(e.getHost())) {
                    String url = e.getNormalizedUrl();
                    if (url != null && url.startsWith("http://")) {
                        return "http";
                    }
                    if (url != null && url.startsWith("https://")) {
                        return "https";
                    }
                }
            }
        }
        return "https";
    }

    private static Component left(Component c) {
        if (c instanceof javax.swing.JComponent jc) {
            jc.setAlignmentX(Component.LEFT_ALIGNMENT);
        }
        return c;
    }
}
