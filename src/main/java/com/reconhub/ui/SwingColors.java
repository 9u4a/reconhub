package com.reconhub.ui;

import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.model.Finding;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import java.awt.Color;
import java.awt.Font;

/** Shared color palette + small chip factory (matches the HTML report palette). */
final class SwingColors {

    static final Color HIGH = new Color(0xff5c5c);
    static final Color MEDIUM = new Color(0xffb020);
    static final Color LOW = new Color(0x4da3ff);
    static final Color INFO = new Color(0x7a8698);
    static final Color WARN = new Color(0xffb020);
    static final Color OK = new Color(0x3fb950);
    static final Color MUTED = new Color(0x9aa4b2);

    private SwingColors() {}

    static Color severityFg(Finding.Severity sev) {
        return switch (sev) {
            case HIGH -> HIGH;
            case MEDIUM -> MEDIUM;
            case LOW -> LOW;
            case INFO -> INFO;
        };
    }

    /** Distinct color per finding category (for the Category column chip). */
    static Color categoryFg(FindingTaxonomy.Category c) {
        return switch (c) {
            case SECRET -> new Color(0xff5c5c);
            case PII -> new Color(0xff7ab8);
            case AUTH -> new Color(0xc586ff);
            case MISCONFIG -> new Color(0xffb020);
            case INFO_LEAK -> new Color(0x4da3ff);
            case API -> new Color(0x3fb950);
            case INJECTION -> new Color(0xff9d4d);
            case COMMENT -> new Color(0x9aa4b2);
            case OTHER -> new Color(0x9aa4b2);
        };
    }

    /** A rounded, tinted label used as a "chip". */
    static JLabel chip(String text, Color color) {
        JLabel l = new JLabel(text);
        l.setOpaque(true);
        l.setBackground(new Color(color.getRed(), color.getGreen(), color.getBlue(), 34));
        l.setForeground(color);
        l.setFont(l.getFont().deriveFont(Font.PLAIN, 12f));
        l.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(color, 1, true),
                BorderFactory.createEmptyBorder(2, 8, 2, 8)));
        return l;
    }
}
