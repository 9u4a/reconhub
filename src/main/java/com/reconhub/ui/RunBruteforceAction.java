package com.reconhub.ui;

import com.reconhub.active.BruteforceEngine;
import com.reconhub.active.BruteforceJob;
import com.reconhub.core.Settings;

import javax.swing.JOptionPane;
import java.awt.Component;

/**
 * Shared "run known-path bruteforce on this host" action, invoked from a host row's right-click menu
 * (Dashboard scorecard, Tech tab). Mirrors the sibling InjectScope extension's confirm-before-run
 * pattern: refuses immediately if the master switch is off, otherwise shows a confirmation dialog
 * (host, estimated requests, throttle) every time — never a silent run.
 */
public final class RunBruteforceAction {

    private RunBruteforceAction() {}

    public static void run(Component owner, BruteforceEngine engine, Settings settings, String host) {
        if (host == null || host.isBlank()) {
            return;
        }
        if (!settings.isBruteforceActiveEnabled()) {
            JOptionPane.showMessageDialog(owner,
                    "Known-path bruteforce is OFF.\nEnable it in the Bruteforce tab first "
                            + "(this sends requests to the target).",
                    "ReconHub — bruteforce inactive", JOptionPane.WARNING_MESSAGE);
            return;
        }
        int estimate = engine.estimateRequests();
        String msg = "About to actively probe known paths against:\n\n"
                + "  https://" + host + "\n\n"
                + "Wordlist size: " + engine.getWordlist().size() + " paths\n"
                + "Estimated requests: ~" + estimate + "\n"
                + "Throttle: " + settings.getBruteforceDelayMs() + " ms delay, concurrency "
                + settings.getBruteforceConcurrency() + ", budget "
                + settings.getBruteforceMaxRequestsPerHost() + "/host\n\n"
                + "Requests will be sent to the target. Proceed?";
        int ok = JOptionPane.showConfirmDialog(owner, msg, "ReconHub — confirm active bruteforce",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) {
            return;
        }
        BruteforceJob job = engine.submit(host);
        if (job == null) {
            JOptionPane.showMessageDialog(owner,
                    "Refused — host is out of scope (check Settings → Scope) or bruteforce is off.",
                    "ReconHub", JOptionPane.WARNING_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(owner,
                    "Started. Track progress in the Bruteforce tab.",
                    "ReconHub", JOptionPane.INFORMATION_MESSAGE);
        }
    }
}
