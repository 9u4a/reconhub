package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.reconhub.active.BruteforceEngine;
import com.reconhub.active.MatchReplaceEngine;
import com.reconhub.active.MatchReplaceTarget;
import com.reconhub.analysis.PayloadCheatsheet;
import com.reconhub.core.Bookmarks;
import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.model.Endpoint;

import javax.swing.JPopupMenu;
import javax.swing.ListSelectionModel;
import java.awt.Component;
import java.awt.Font;
import java.util.ArrayList;
import java.util.List;

/** Table of deduplicated endpoints with the request/response viewer and shared row menu. */
public final class EndpointsPanel extends AbstractTablePanel<Endpoint> {

    private static final String[] COLS =
            {"Method", "Host", "Path", "Status", "Content-Type", "Params", "Auth", "Source"};
    private static final int COL_STATUS = 3;
    private static final int COL_AUTH = 6;

    private final DataStore store;
    private final PayloadCheatsheet cheatsheet;
    private final MessageViewer viewer;
    private BruteforceEngine bruteforce;
    private Settings settings;
    private MatchReplaceEngine matchReplace;

    // Burp-History-filter-style checklist quick filters (0.40.0+) -- Method/Status/Content-Type are
    // exactly the kind of open-ended-but-repetitive column Burp's own filter dialog offers checkboxes
    // for, unlike e.g. Path which is different on every row and wouldn't benefit from a checklist.
    private final ColumnValueFilter<Endpoint> methodFilter =
            new ColumnValueFilter<>("Method", Endpoint::getMethod);
    private final ColumnValueFilter<Endpoint> statusFilter = new ColumnValueFilter<>("Status",
            e -> e.getLastStatusCode() == 0 ? null : String.valueOf(e.getLastStatusCode()));
    private final ColumnValueFilter<Endpoint> ctFilter =
            new ColumnValueFilter<>("Type", e -> shortCt(e.getContentType()));

    public EndpointsPanel(DataStore store, MontoyaApi api, PayloadCheatsheet cheatsheet, Bookmarks bookmarks) {
        super(api, bookmarks);
        this.store = store;
        this.cheatsheet = cheatsheet;
        this.viewer = new MessageViewer(api);
        installDetail(viewer);

        methodFilter.setOnChange(this::reapplyFilter);
        statusFilter.setOnChange(this::reapplyFilter);
        ctFilter.setOnChange(this::reapplyFilter);
        addToToolbar(methodFilter.component());
        addToToolbar(statusFilter.component());
        addToToolbar(ctFilter.component());

        // MULTIPLE_INTERVAL_SELECTION (0.42.0): lets Ctrl/Shift pick several endpoints at once for the
        // "Send N selected with Match & Replace…" menu item below -- AbstractTablePanel's own default
        // (SINGLE_SELECTION) is left untouched, so Parameters/Findings/JS Assets/Tech are unaffected.
        // installContextMenu()'s "only move selection when the clicked row is outside it" logic already
        // preserves a multi-selection across a right-click (unlike Dashboard's separate installPopup,
        // which needed that fix added in 0.41.1 -- this one already had it), so the existing single-
        // target menu items (Copy/Repeater/Intruder/etc.) keep working exactly as before, unaffected by
        // turning this on.
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
    }

    @Override protected boolean hasRowFilter() { return true; }

    @Override
    protected boolean rowIncluded(Endpoint e) {
        return e == null || (methodFilter.test(e) && statusFilter.test(e) && ctFilter.test(e));
    }

    @Override
    public void refreshData() {
        super.refreshData();
        List<Endpoint> rows = store.snapshotEndpoints();
        methodFilter.refreshAvailableValues(rows);
        statusFilter.refreshAvailableValues(rows);
        ctFilter.refreshAvailableValues(rows);
    }

    @Override protected String rowKey(Endpoint e) { return e == null ? null : e.key(); }

    /** The currently-selected endpoints, in table (view) order -- used by the Match & Replace bulk-send
     * menu item, which (unlike the single-target Copy/Repeater/etc. items above) needs the whole
     * selection, not just the row that was right-clicked. */
    List<Endpoint> selectedEndpoints() {
        List<Endpoint> out = new ArrayList<>();
        for (int view : table.getSelectedRows()) {
            Endpoint e = rowAt(view);
            if (e != null) {
                out.add(e);
            }
        }
        return out;
    }

    /** {@link #selectedEndpoints()}, converted to the type-agnostic shape {@code active
     * .MatchReplaceEngine} actually needs (0.43.0 -- every source panel builds these the same way from
     * its own row type). */
    private List<MatchReplaceTarget> selectedMatchReplaceTargets() {
        List<MatchReplaceTarget> out = new ArrayList<>();
        for (Endpoint e : selectedEndpoints()) {
            out.add(new MatchReplaceTarget(e.getHost(), e.getPath(), e.getMethod(), e.getMessages()));
        }
        return out;
    }

    /** Wires the (ACTIVE) known-path bruteforce action for this tab's right-click menu; called once. */
    public void setBruteforce(BruteforceEngine engine, Settings settings) {
        this.bruteforce = engine;
        this.settings = settings;
    }

    /** Wires the (ACTIVE) Match & Replace bulk-send action for this tab's right-click menu; called
     * once. */
    public void setMatchReplace(MatchReplaceEngine engine, Settings settings) {
        this.matchReplace = engine;
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
        addDeleteHostMenuItem(menu, store, e.getHost());

        if (matchReplace != null && settings != null) {
            List<MatchReplaceTarget> selected = selectedMatchReplaceTargets();
            // Falls back to just the right-clicked row when nothing is multi-selected (e.g. a plain
            // single click) -- same "clicked row is the default target" rule the single-target items
            // above already follow.
            List<MatchReplaceTarget> targets = selected.isEmpty()
                    ? List.of(new MatchReplaceTarget(e.getHost(), e.getPath(), e.getMethod(), e.getMessages()))
                    : selected;
            menu.addSeparator();
            addMenuItem(menu, "Send " + targets.size() + " selected with Match & Replace… (active)", true,
                    () -> MatchReplaceDialog.show(this, matchReplace, settings, targets));
        }
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
        if (e == null || selected) {
            return;
        }
        if (viewColumn == COL_STATUS) {
            // Color the Status cell by HTTP status class -- 2xx OK, 5xx worth a second look (server
            // errors can leak stack traces/paths), everything else (3xx/4xx) stays the default color
            // since 404 in particular is by far the most common status in a recon dataset and coloring
            // it would just be noise.
            int status = e.getLastStatusCode();
            if (status >= 200 && status < 300) {
                comp.setForeground(SwingColors.OK);
            } else if (status >= 500) {
                comp.setForeground(SwingColors.WARN);
            }
            return;
        }
        if (viewColumn != COL_AUTH) {
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
