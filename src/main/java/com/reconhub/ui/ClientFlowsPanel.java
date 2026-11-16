package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.reconhub.analysis.ClientFlowLeads;
import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.core.Bookmarks;
import com.reconhub.core.DataStore;
import com.reconhub.core.Hosts;
import com.reconhub.model.ClientFlow;
import com.reconhub.model.Endpoint;

import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPopupMenu;
import javax.swing.JTabbedPane;
import java.awt.Component;
import java.awt.Font;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/**
 * Client Flows (0.59.0): one row per API request the front-end code sends -- method, path template,
 * body/query keys, auth source, the function and route/handler that trigger it -- with Seen (matching
 * captured traffic) and an IDOR / no-auth hint. Passive: "Send template to Repeater" only fills a
 * Repeater tab, it never sends.
 */
public final class ClientFlowsPanel extends AbstractTablePanel<ClientFlow> {

    private static final String[] COLS = {"Method", "Path", "Body keys", "Query keys", "Auth", "Seen",
            "Category", "Function", "Trigger", "Via", "Hint", "JS file"};
    private static final int COL_METHOD = 0;
    private static final int COL_PATH = 1;
    private static final int COL_AUTH = 4;
    private static final int COL_SEEN = 5;
    private static final int COL_CATEGORY = 6;
    private static final int COL_HINT = 10;
    private static final int COL_JS = 11;
    static final String BOOKMARK_PREFIX = "cf:";

    private final DataStore store;
    private final MessageViewer codeViewer;
    private final MessageViewer seenViewer;
    private final JTabbedPane detailTabs = new JTabbedPane();
    private final JCheckBox untestedOnly = new JCheckBox("Untested only", false);
    private final JLabel summary = new JLabel(" ");
    private final ColumnValueFilter<ClientFlow> hostFilter =
            new ColumnValueFilter<>("Host", f -> Hosts.label(f.getHost()));
    private final ColumnValueFilter<ClientFlow> methodFilter =
            new ColumnValueFilter<>("Method", ClientFlow::getMethod);
    private DashboardPanel.Navigator navigator;

    // Identity memos: Seen is recomputed only when the endpoint or flow snapshot list changes.
    private List<Endpoint> lastEndpoints;
    private List<ClientFlow> lastFlows;
    private Map<ClientFlow, Endpoint> seen = new IdentityHashMap<>();
    private final Map<ClientFlow, String[]> typeCache = new IdentityHashMap<>();   // {type, hint}

    public ClientFlowsPanel(DataStore store, MontoyaApi api, Bookmarks bookmarks) {
        super(api, bookmarks);
        this.store = store;
        this.codeViewer = new MessageViewer(api);
        this.seenViewer = new MessageViewer(api);
        detailTabs.addTab("Code", codeViewer);
        detailTabs.addTab("Captured request", seenViewer);
        installDetail(detailTabs, codeViewer);

        methodFilter.setOnChange(this::onFilterChanged);
        addToToolbar(methodFilter.component());
        hostFilter.setOnChange(this::onFilterChanged);
        addToToolbar(hostFilter.component());
        untestedOnly.setToolTipText("Only flows with no matching request in captured traffic -- the untested surface");
        untestedOnly.addActionListener(e -> onFilterChanged());
        addToToolbar(untestedOnly);
        addToToolbar(summary);
    }

    private void onFilterChanged() {
        reapplyFilter();
        updateSummary();
    }

    public void setNavigator(DashboardPanel.Navigator navigator) {
        this.navigator = navigator;
    }

    @Override protected String rowKey(ClientFlow f) { return f == null ? null : BOOKMARK_PREFIX + f.key(); }

    @Override protected boolean hasRowFilter() { return true; }

    @Override
    protected boolean rowIncluded(ClientFlow f) {
        if (f == null) return true;
        if (untestedOnly.isSelected() && seen.get(f) != null) return false;
        return hostFilter.test(f) && methodFilter.test(f);
    }

    @Override
    protected List<ClientFlow> supplyRows() {
        List<ClientFlow> flows = store.snapshotClientFlows();
        List<Endpoint> endpoints = store.snapshotEndpoints();
        if (flows != lastFlows || endpoints != lastEndpoints) {
            ClientFlowLeads.SeenIndex idx = ClientFlowLeads.index(endpoints);
            Map<ClientFlow, Endpoint> m = new IdentityHashMap<>();
            for (ClientFlow f : flows) {
                Endpoint e = idx.find(f);
                if (e != null) m.put(f, e);
            }
            seen = m;
            typeCache.clear();   // keys/auth may have merged in since
            lastFlows = flows;
            lastEndpoints = endpoints;
        }
        return flows;
    }

    @Override
    public void refreshData() {
        super.refreshData();
        hostFilter.refreshAvailableValues(rows());
        methodFilter.refreshAvailableValues(rows());
        updateSummary();
    }

    private void updateSummary() {
        int visible = 0;
        int untested = 0;
        int idor = 0;
        for (ClientFlow f : rows()) {
            if (!rowIncluded(f)) continue;
            visible++;
            if (seen.get(f) == null) untested++;
            if (ClientFlowLeads.TYPE_IDOR.equals(typeOf(f)[0])) idor++;
        }
        summary.setText("  " + visible + " flows  ·  untested " + untested + "  ·  IDOR candidates " + idor);
    }

    private String[] typeOf(ClientFlow f) {
        return typeCache.computeIfAbsent(f, x -> new String[]{ClientFlowLeads.type(x), ClientFlowLeads.hint(x)});
    }

    @Override
    protected void onRowSelected(ClientFlow f) {
        if (f == null) {
            codeViewer.show(null);
            codeViewer.setSearchExpression("");
            codeViewer.setInfo(" ");
            seenViewer.show(null);
            seenViewer.setInfo(" ");
            detailTabs.setTitleAt(1, "Captured request");
            return;
        }
        codeViewer.show(f.getMessages());
        codeViewer.setSearchExpression(f.getCallSite());
        codeViewer.setInfo(f.getMethod() + " " + f.getPath() + "   |   " + f.getVia()
                + (f.getFunction().isEmpty() ? "" : "   |   in " + f.getFunction() + "()")
                + "   |   " + f.getJsUrl());
        Endpoint e = seen.get(f);
        seenViewer.show(e == null ? null : e.getMessages());
        seenViewer.setInfo(e == null ? "Not seen in captured traffic -- untested"
                : "Captured: " + e.getMethod() + " " + e.getNormalizedUrl() + "  (" + e.getLastStatusCode() + ")");
        detailTabs.setTitleAt(1, e == null ? "Captured request" : "Captured request ✓");
    }

    @Override protected HttpRequestResponse rowMessages(ClientFlow f) {
        Endpoint e = f == null ? null : seen.get(f);
        return e != null ? e.getMessages() : f == null ? null : f.getMessages();
    }

    @Override
    protected void extraMenuItems(JPopupMenu menu, ClientFlow f) {
        if (f == null) return;
        addMenuItem(menu, "Send template to Repeater (sends nothing)", true, () -> sendTemplate(f));
        if (navigator != null && !f.getJsUrl().isEmpty()) {
            addMenuItem(menu, "Open this JS file in JS Assets", true, () -> navigator.filterJsAssets(f.getJsUrl()));
        }
        Endpoint e = seen.get(f);
        if (navigator != null && e != null) {
            addMenuItem(menu, "Show captured endpoint in Endpoints", true, () -> navigator.filterEndpoints(e.getPath()));
        }
        addDeleteHostMenuItem(menu, store, f.getHost());
    }

    /** Fills a Repeater tab with the templated request. Never sends traffic. */
    private void sendTemplate(ClientFlow f) {
        try {
            ClientFlowLeads.Template t = ClientFlowLeads.template(f);
            HttpRequest req = HttpRequest.httpRequest(HttpService.httpService(t.host(), t.port(), t.secure()), t.raw());
            api.repeater().sendToRepeater(req, "RH " + f.getMethod() + " " + f.pathOnly());
        } catch (RuntimeException ex) {
            api.logging().logToError("ReconHub: could not build a Repeater template for " + f.key() + ": " + ex);
        }
    }

    @Override
    protected void styleCell(Component comp, ClientFlow f, int viewColumn, boolean selected) {
        if (f == null) return;
        String type = typeOf(f)[0];
        if (!selected) {
            if (viewColumn == COL_CATEGORY) {
                comp.setForeground(SwingColors.categoryFg(FindingTaxonomy.categoryOf(type)));
            }
        }
        comp.setFont(comp.getFont().deriveFont(viewColumn == COL_METHOD ? Font.BOLD : Font.PLAIN));
        if (comp instanceof JComponent jc) {
            String tip = switch (viewColumn) {
                case COL_PATH -> f.getCallSite();
                case COL_SEEN -> "Y = a matching request is in captured traffic, N = only in JS (untested)";
                case COL_HINT -> typeOf(f)[1];
                case COL_JS -> String.join("\n", f.getJsUrls());
                case COL_AUTH -> f.getAuth().isEmpty() ? "No explicit auth header in the call (cookies may still apply)" : null;
                default -> null;
            };
            jc.setToolTipText(tip == null || tip.isBlank() ? null : tip);
        }
    }

    @Override protected String rowUrl(ClientFlow f) {
        return f != null && f.getJsUrl().startsWith("http") ? f.getJsUrl() : null;
    }

    @Override protected String[] columns() { return COLS; }

    @Override protected int[] columnWidths() {
        return new int[]{60, 260, 160, 120, 140, 45, 70, 120, 140, 140, 260, 200};
    }

    @Override protected Object valueAt(ClientFlow f, int c) {
        return switch (c) {
            case COL_METHOD -> f.getMethod();
            case COL_PATH -> f.getPath();
            case 2 -> String.join(", ", f.getBodyKeys());
            case 3 -> String.join(", ", f.getQueryKeys());
            case COL_AUTH -> f.getAuth().isEmpty() ? "(none)" : f.getAuth();
            case COL_SEEN -> seen.get(f) != null ? "Y" : "N";
            case COL_CATEGORY -> {
                String t = typeOf(f)[0];
                yield t.equals(ClientFlowLeads.TYPE) ? "Flow" : t.substring(t.indexOf(':') + 2);
            }
            case 7 -> f.getFunction();
            case 8 -> f.getTrigger();
            case 9 -> f.getVia();
            case COL_HINT -> typeOf(f)[1];
            case COL_JS -> fileLabel(f.getJsUrl());
            default -> "";
        };
    }

    /** Last path segment of a JS URL, or the URL itself when it has none. Pure/static. */
    static String fileLabel(String url) {
        if (url == null || url.isBlank()) return "";
        String u = url;
        int q = u.indexOf('?');
        if (q >= 0) u = u.substring(0, q);
        int slash = u.lastIndexOf('/');
        String name = slash >= 0 ? u.substring(slash + 1) : u;
        return name.isBlank() ? url : name;
    }
}
