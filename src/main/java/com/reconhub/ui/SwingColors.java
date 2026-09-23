package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.Theme;
import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.model.Finding;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;

/**
 * Shared color palette + small chip factory (matches the HTML report palette). Theme-aware since
 * 0.37.0: every color here was originally tuned dark-only (this codebase had no light-theme users
 * until Burp's own light theme was accounted for) -- {@link #isDark()} picks between two variants at
 * call time. Burp's {@code Theme} API has no change-notification callback (confirmed via {@code
 * javap} against montoya-api 2023.12.1 -- {@code UserInterface} exposes only a poll-only {@code
 * currentTheme()}), so callers that need to react to a live theme flip must re-poll (see {@code
 * MainTab}'s refresh timer) rather than register a listener here.
 */
final class SwingColors {

    private static volatile MontoyaApi api;

    private SwingColors() {}

    /** Call once at extension startup, before any UI is built. */
    static void init(MontoyaApi montoyaApi) {
        api = montoyaApi;
    }

    /** True when the active Burp theme is dark (or unknown -- every color here was originally tuned
     * for a dark background, so that's the safe default before {@link #init} has run). */
    static boolean isDark() {
        MontoyaApi a = api;
        return a == null || a.userInterface().currentTheme() != Theme.LIGHT;
    }

    // ---- severity / category palette (unchanged between themes -- these are chip-style saturated
    // colors on a translucent tinted background, which reads fine on either background; only the
    // structural colors below (lines, banners) were actually broken on light) ----

    static final Color HIGH = new Color(0xff5c5c);
    static final Color MEDIUM = new Color(0xffb020);
    static final Color LOW = new Color(0x4da3ff);
    static final Color INFO = new Color(0x7a8698);
    static final Color WARN = new Color(0xffb020);
    static final Color OK = new Color(0x3fb950);
    static final Color MUTED = new Color(0x9aa4b2);
    static final Color ACCENT = new Color(0x4da3ff);

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

    // ---- structural colors -- these were the ones actually tuned dark-only (a near-black separator
    // line, a near-black-red alert banner) and need a real light-theme variant, not just a translucent
    // tint of an already-legible color. Absorbed here from DashboardPanel/SettingsPanel/BruteforcePanel
    // (0.37.0) so there's one definition instead of four independently-hand-tuned copies. ----

    private static final Color LINE_DARK = new Color(0x2a313b);
    private static final Color LINE_LIGHT = new Color(0xd0d5dc);

    /** Hairline separator / border color (section underlines, stat-pill borders). */
    static Color line() {
        return isDark() ? LINE_DARK : LINE_LIGHT;
    }

    private static final Color BANNER_BG_DARK = new Color(0x3a1414);
    private static final Color BANNER_FG_DARK = new Color(0xff8a8a);
    private static final Color BANNER_BG_LIGHT = new Color(0xffe5e5);
    private static final Color BANNER_FG_LIGHT = new Color(0xb02020);

    /** The Bruteforce tab's ACTIVE banner background. */
    static Color bannerBg() {
        return isDark() ? BANNER_BG_DARK : BANNER_BG_LIGHT;
    }

    /** The Bruteforce tab's ACTIVE banner text/border color. */
    static Color bannerFg() {
        return isDark() ? BANNER_FG_DARK : BANNER_FG_LIGHT;
    }

    // ---- zebra striping (0.37.0+) -- every table in ReconHub renders every other row very slightly
    // tinted, purely so a wide table with many columns stays easy to track by eye across the row. ----

    /** Blends {@code base} toward {@code toward} by {@code amount} (0..1). Shared by zebra striping
     * and the bookmark row tint (AbstractTablePanel). */
    static Color blend(Color base, Color toward, double amount) {
        int r = (int) Math.round(base.getRed() * (1 - amount) + toward.getRed() * amount);
        int g = (int) Math.round(base.getGreen() * (1 - amount) + toward.getGreen() * amount);
        int b = (int) Math.round(base.getBlue() * (1 - amount) + toward.getBlue() * amount);
        return new Color(r, g, b);
    }

    /** Zebra-stripe background for an odd view row, derived from {@code tableBg} (the table/selection
     * background actually in play) rather than a hardcoded pair of light/dark constants -- a single
     * small blend toward {@link #MUTED} reads correctly on either theme without a branch. */
    static Color stripe(Color tableBg) {
        return blend(tableBg, MUTED, 0.08);
    }

    /**
     * A striping-only {@link TableCellRenderer} for the tables outside {@code AbstractTablePanel}
     * (Dashboard's host/type/notable tables, the Bruteforce tab's job/hit tables) that don't already
     * have a custom renderer of their own. Register it for both {@code Object.class} and {@code
     * Integer.class} -- {@code JTable} otherwise renders any {@code Integer}-typed column (declared via
     * {@code getColumnClass}) with its own built-in right-aligned {@code Number} renderer, which would
     * silently skip whatever is registered only for {@code Object.class} (the exact gap that made
     * numeric columns in the data tabs look inconsistent before this).
     */
    static TableCellRenderer stripedRenderer() {
        return new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value, boolean sel,
                                                            boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, value, sel, focus, row, col);
                if (sel) {
                    c.setBackground(t.getSelectionBackground());
                    c.setForeground(t.getSelectionForeground());
                } else {
                    c.setBackground(row % 2 == 1 ? stripe(t.getBackground()) : t.getBackground());
                    c.setForeground(t.getForeground());
                }
                // Swing's own built-in Number renderer right-aligns numeric columns; replicate that
                // here since this renderer replaces it (registered for Integer.class too, see below).
                setHorizontalAlignment(value instanceof Number ? SwingConstants.RIGHT : SwingConstants.LEFT);
                return c;
            }
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
