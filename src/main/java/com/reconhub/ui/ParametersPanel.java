package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.active.BruteforceEngine;
import com.reconhub.analysis.ParameterClassifier;
import com.reconhub.analysis.PayloadCheatsheet;
import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.model.ParameterInfo;

import javax.swing.JComponent;
import javax.swing.JPopupMenu;
import java.awt.Component;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;

/**
 * Table of parameters, one row per (endpoint, parameter). Selecting a row shows the representative
 * request/response below. The "Class" column carries passive vulnerability-class hints derived from
 * the parameter name (recon triage only).
 */
public final class ParametersPanel extends AbstractTablePanel<ParameterInfo> {

    private static final String[] COLS =
            {"Host", "Endpoint", "Type", "Name", "Value", "Class", "Reflected", "Seen"};
    private static final int COL_CLASS = 5;
    private static final int COL_REFLECTED = 6;

    private final DataStore store;
    private final PayloadCheatsheet cheatsheet;
    private final MessageViewer viewer;
    private BruteforceEngine bruteforce;
    private Settings settings;

    public ParametersPanel(DataStore store, MontoyaApi api, PayloadCheatsheet cheatsheet) {
        super(api);
        this.store = store;
        this.cheatsheet = cheatsheet;
        this.viewer = new MessageViewer(api);
        installDetail(viewer);
    }

    /** Wires the (ACTIVE) known-path bruteforce action for this tab's right-click menu; called once. */
    public void setBruteforce(BruteforceEngine engine, Settings settings) {
        this.bruteforce = engine;
        this.settings = settings;
    }

    @Override
    protected void extraMenuItems(JPopupMenu menu, ParameterInfo p) {
        if (p == null) {
            return;
        }
        boolean addedAny = false;
        if (cheatsheet != null) {
            List<String> classes = ParameterClassifier.classify(p.getName());
            List<PayloadCheatsheet.Set> sets = new ArrayList<>();
            for (String c : classes) {
                PayloadCheatsheet.Set s = cheatsheet.forClass(c);
                if (s != null) {
                    sets.add(s);
                }
            }
            if (!sets.isEmpty()) {
                menu.addSeparator();
                addMenuItem(menu, "View payload cheatsheet…", true,
                        () -> CheatsheetDialog.showFor(this, p.getName(), sets));
                addedAny = true;
            }
        }
        if (bruteforce != null && p.getHost() != null && !p.getHost().isBlank()) {
            if (!addedAny) {
                menu.addSeparator();
            }
            addMenuItem(menu, "Run known-path bruteforce on this host… (active)", true,
                    () -> RunBruteforceAction.run(this, bruteforce, settings, p.getHost()));
        }
    }

    @Override
    protected HttpRequestResponse rowMessages(ParameterInfo p) {
        return p == null ? null : p.getMessages();
    }

    @Override
    protected String rowUrl(ParameterInfo p) {
        HttpRequestResponse rr = p == null ? null : p.getMessages();
        return rr != null && rr.request() != null ? rr.request().url() : null;
    }

    @Override
    protected void styleCell(Component comp, ParameterInfo p, int viewColumn, boolean selected) {
        if (p == null) {
            return;
        }
        String classes = ParameterClassifier.classifyJoined(p.getName());
        boolean hasClass = !classes.isEmpty();

        if (comp instanceof JComponent jc) {
            jc.setToolTipText(viewColumn == COL_CLASS && hasClass ? classes : null);
        }

        if (!selected) {
            if (p.isReflected()) {
                comp.setForeground(SwingColors.WARN);          // reflected = XSS candidate
            } else if (hasClass && viewColumn == COL_CLASS) {
                comp.setForeground(SwingColors.LOW);           // class hint = accent
            }
        }
        boolean bold = (viewColumn == COL_REFLECTED && p.isReflected())
                || (viewColumn == COL_CLASS && hasClass);
        comp.setFont(comp.getFont().deriveFont(bold ? Font.BOLD : Font.PLAIN));
    }

    @Override
    protected void onRowSelected(ParameterInfo p) {
        if (p == null) {
            viewer.show(null);
            viewer.setInfo(" ");
            return;
        }
        viewer.show(p.getMessages());
        String classes = ParameterClassifier.classifyJoined(p.getName());
        StringBuilder sb = new StringBuilder();
        sb.append(p.getLocation().name()).append(" parameter \"").append(p.getName())
                .append("\" on ").append(p.getEndpointPath());
        if (!classes.isEmpty()) {
            sb.append("   |   class: ").append(classes);
        }
        viewer.setInfo(sb.toString());
    }

    @Override protected boolean supportsBodySearch() { return true; }

    @Override
    protected String searchableBody(ParameterInfo p) {
        return p == null ? null : MessageViewer.toSearchText(p.getMessages());
    }

    @Override protected List<ParameterInfo> supplyRows() { return store.snapshotParameters(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{150, 250, 60, 150, 190, 150, 80, 55};
    }

    @Override protected Object valueAt(ParameterInfo p, int c) {
        return switch (c) {
            case 0 -> p.getHost();
            case 1 -> p.getEndpointPath();
            case 2 -> p.getLocation().name();
            case 3 -> p.getName();
            case 4 -> p.getExampleValue();
            case 5 -> ParameterClassifier.classifyJoined(p.getName());
            case 6 -> p.isReflected() ? "yes" : "";
            case 7 -> p.getSeen();
            default -> "";
        };
    }
}
