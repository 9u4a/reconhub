package com.reconhub.ui;

import com.reconhub.active.BruteforceEngine;
import com.reconhub.active.BruteforceJob;
import com.reconhub.core.Settings;

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
 * row's right-click menu. Mirrors the sibling InjectScope extension's confirm-before-run pattern:
 * refuses immediately if the master switch is off, otherwise shows a confirmation dialog — with the
 * target address in an editable field, defaulted from the row but changeable before running — every
 * time. Never a silent run.
 */
public final class RunBruteforceAction {

    private RunBruteforceAction() {}

    /** @param suggestedTarget a bare host ({@code "example.com"}) or a full origin
     *                         ({@code "https://example.com:8443"}); scheme defaults to https. */
    public static void run(Component owner, BruteforceEngine engine, Settings settings,
                           String suggestedTarget) {
        if (suggestedTarget == null || suggestedTarget.isBlank()) {
            return;
        }
        if (!settings.isBruteforceActiveEnabled()) {
            JOptionPane.showMessageDialog(owner,
                    "Known-path bruteforce is OFF.\nEnable it in the Bruteforce tab first "
                            + "(this sends requests to the target).",
                    "ReconHub — bruteforce inactive", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String defaultUrl = suggestedTarget.contains("://") ? suggestedTarget : "https://" + suggestedTarget;
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
                    "Refused — target could not be parsed, is out of scope "
                            + "(check Settings → Scope), or bruteforce is off.",
                    "ReconHub", JOptionPane.WARNING_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(owner,
                    "Started against " + job.getHost() + ". Track progress in the Bruteforce tab.",
                    "ReconHub", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private static Component left(Component c) {
        if (c instanceof javax.swing.JComponent jc) {
            jc.setAlignmentX(Component.LEFT_ALIGNMENT);
        }
        return c;
    }
}
