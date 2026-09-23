package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.active.BruteforceEngine;
import com.reconhub.core.Bookmarks;
import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.model.TechInfo;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.List;

/** Per-host technologies + missing security headers, with a readable chip detail panel. */
public final class TechPanel extends AbstractTablePanel<TechInfo> {

    private static final String[] COLS = {"Host", "Technologies", "Missing security headers"};

    private final DataStore store;
    private final JPanel detailBody = new JPanel();
    private BruteforceEngine bruteforce;
    private Settings settings;

    public TechPanel(DataStore store, MontoyaApi api, Bookmarks bookmarks) {
        super(api, bookmarks);
        this.store = store;
        detailBody.setLayout(new BoxLayout(detailBody, BoxLayout.Y_AXIS));
        detailBody.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        installDetail(new JScrollPane(detailBody));
    }

    @Override protected String rowKey(TechInfo t) { return t == null ? null : t.key(); }

    /** Wires the (ACTIVE) known-path bruteforce action for this tab's right-click menu; called once. */
    public void setBruteforce(BruteforceEngine engine, Settings settings) {
        this.bruteforce = engine;
        this.settings = settings;
    }

    @Override
    protected void extraMenuItems(JPopupMenu menu, TechInfo t) {
        if (t == null) {
            return;
        }
        addBruteforceMenuItem(menu, bruteforce, settings, store, t.getHost());
    }

    @Override
    protected void onRowSelected(TechInfo t) {
        detailBody.removeAll();
        if (t != null) {
            detailBody.add(header(t.getHost()));
            detailBody.add(chipRow("Technologies", t.getTechnologies(), SwingColors.OK));
            detailBody.add(chipRow("Missing security headers",
                    t.getMissingSecurityHeaders(), SwingColors.WARN));
        }
        detailBody.revalidate();
        detailBody.repaint();
    }

    private static JLabel header(String host) {
        JLabel l = new JLabel(host);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 14f));
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setBorder(BorderFactory.createEmptyBorder(0, 0, 6, 0));
        return l;
    }

    private static JPanel chipRow(String title, java.util.Set<String> items, java.awt.Color color) {
        JPanel wrap = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 3));
        wrap.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel t = new JLabel(title + ":");
        t.setForeground(SwingColors.MUTED);
        wrap.add(t);
        if (items.isEmpty()) {
            wrap.add(new JLabel("(none)"));
        } else {
            for (String s : items) {
                wrap.add(SwingColors.chip(s, color));
            }
        }
        return wrap;
    }

    @Override
    protected String rowUrl(TechInfo t) {
        if (t == null || t.getHost() == null || t.getHost().isBlank()) {
            return null;
        }
        // Reuse the scheme actually observed for this host (see RunBruteforceAction.inferScheme and the
        // CLAUDE.md note on this exact bug class) -- a hardcoded https:// sends Open-in-browser/Send-to-
        // Repeater at the wrong scheme for any http-only host (e.g. a local dev server).
        return RunBruteforceAction.inferScheme(store, t.getHost()) + "://" + t.getHost();
    }

    @Override
    protected void styleCell(Component comp, TechInfo t, int viewColumn, boolean selected) {
        if (t == null || selected) {
            return;
        }
        // Warn-color the "Missing security headers" column when there are any.
        if (viewColumn == 2 && !t.getMissingSecurityHeaders().isEmpty()) {
            comp.setForeground(SwingColors.WARN);
        }
    }

    @Override protected List<TechInfo> supplyRows() { return store.snapshotTech(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{220, 400, 400};
    }

    @Override protected Object valueAt(TechInfo t, int c) {
        return switch (c) {
            case 0 -> t.getHost();
            case 1 -> String.join(", ", t.getTechnologies());
            case 2 -> String.join(", ", t.getMissingSecurityHeaders());
            default -> "";
        };
    }
}
