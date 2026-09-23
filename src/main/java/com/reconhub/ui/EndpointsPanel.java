package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.active.BruteforceEngine;
import com.reconhub.analysis.PayloadCheatsheet;
import com.reconhub.core.Bookmarks;
import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.model.Endpoint;

import javax.swing.JPopupMenu;
import java.awt.Component;
import java.awt.Font;
import java.util.List;

/** Table of deduplicated endpoints with the request/response viewer and shared row menu. */
public final class EndpointsPanel extends AbstractTablePanel<Endpoint> {

    private static final String[] COLS =
            {"Method", "Host", "Path", "Status", "Content-Type", "Params", "Auth", "Source"};
    private static final int COL_AUTH = 6;

    private final DataStore store;
    private final PayloadCheatsheet cheatsheet;
    private final MessageViewer viewer;
    private BruteforceEngine bruteforce;
    private Settings settings;

    public EndpointsPanel(DataStore store, MontoyaApi api, PayloadCheatsheet cheatsheet, Bookmarks bookmarks) {
        super(api, bookmarks);
        this.store = store;
        this.cheatsheet = cheatsheet;
        this.viewer = new MessageViewer(api);
        installDetail(viewer);
    }

    @Override protected String rowKey(Endpoint e) { return e == null ? null : e.key(); }

    /** Wires the (ACTIVE) known-path bruteforce action for this tab's right-click menu; called once. */
    public void setBruteforce(BruteforceEngine engine, Settings settings) {
        this.bruteforce = engine;
        this.settings = settings;
    }

    @Override
    protected void extraMenuItems(JPopupMenu menu, Endpoint e) {
        if (e == null) {
            return;
        }
        // Body-structure-driven cheatsheets (XXE on XML/SOAP endpoints) -- not name-based, so keyed
        // off Content-Type instead of a ParameterClassifier class.
        PayloadCheatsheet.Set xxe = cheatsheet == null ? null : cheatsheet.forContentType(e.getContentType());
        if (xxe != null) {
            menu.addSeparator();
            addMenuItem(menu, "View payload cheatsheet (XXE)…", true,
                    () -> CheatsheetDialog.showFor(this, e.getPath(), List.of(xxe)));
        }
        addBruteforceMenuItem(menu, bruteforce, settings, store, e.getHost());
    }

    @Override
    protected void onRowSelected(Endpoint e) {
        if (e == null) {
            viewer.show(null);
            viewer.setInfo(" ");
            return;
        }
        viewer.show(e.getMessages());
        StringBuilder info = new StringBuilder();
        if (!e.getParamNames().isEmpty()) {
            info.append("Params: ").append(String.join(", ", e.getParamNames()));
        }
        if (!e.getOrigins().isEmpty()) {
            if (info.length() > 0) {
                info.append("   |   ");
            }
            info.append("Found in: ").append(String.join(", ", e.getOrigins()));
        }
        if (info.length() == 0) {
            info.append(e.getMethod()).append(' ').append(e.getNormalizedUrl());
        }
        viewer.setInfo(info.toString());
    }

    @Override
    protected String rowUrl(Endpoint e) {
        return e != null && e.getNormalizedUrl().startsWith("http") ? e.getNormalizedUrl() : null;
    }

    @Override
    protected HttpRequestResponse rowMessages(Endpoint e) {
        return e == null ? null : e.getMessages();
    }

    @Override protected boolean supportsBodySearch() { return true; }

    @Override
    protected String searchableBody(Endpoint e) {
        return e == null ? null : MessageViewer.toSearchText(e.getMessages());
    }

    @Override protected List<Endpoint> supplyRows() { return store.snapshotEndpoints(); }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{60, 160, 320, 60, 150, 60, 60, 90};
    }

    // Status (3) and Params (5) are numeric -- declared so the sorter compares them as numbers
    // instead of lexicographically (which would put e.g. "10" before "2").
    @Override protected Class<?>[] columnClasses() {
        return new Class<?>[]{null, null, null, Integer.class, null, Integer.class, null, null};
    }

    @Override protected Object valueAt(Endpoint e, int c) {
        return switch (c) {
            case 0 -> e.getMethod();
            case 1 -> e.getHost();
            case 2 -> e.getPath();
            case 3 -> e.getLastStatusCode() == 0 ? null : e.getLastStatusCode();
            case 4 -> shortCt(e.getContentType());
            case 5 -> e.getParamCount();
            case COL_AUTH -> e.authStatus();
            case 7 -> String.join(",", e.getSources());
            default -> "";
        };
    }

    @Override
    protected void styleCell(Component comp, Endpoint e, int viewColumn, boolean selected) {
        if (e == null || selected || viewColumn != COL_AUTH) {
            return;
        }
        // Highlight endpoints observed WITHOUT credentials (potential unauthenticated access).
        String auth = e.authStatus();
        boolean anon = auth.equals("anon") || auth.equals("both");
        boolean twoxx = e.getLastStatusCode() >= 200 && e.getLastStatusCode() < 300;
        if (anon && twoxx) {
            comp.setForeground(SwingColors.severityFg(com.reconhub.model.Finding.Severity.MEDIUM));
            comp.setFont(comp.getFont().deriveFont(Font.BOLD));
        }
    }

    private static String shortCt(String ct) {
        return ct == null ? "" : ct.split(";")[0].trim();
    }
}
