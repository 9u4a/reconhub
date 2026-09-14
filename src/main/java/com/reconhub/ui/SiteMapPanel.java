package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;

import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.JTree;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.net.URI;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Burp-style Site Map: a host → path tree on the left (hosts shown as {@code host:port} with a
 * scheme-colored lock icon, folders and file items with tree icons), a table of the requests under
 * the selected node on the top-right, and a read-only request/response viewer on the bottom-right.
 */
public final class SiteMapPanel extends JPanel implements Refreshable {

    /**
     * Tree node payload. {@code host} nodes are the top-level authority rows (carry scheme flags for
     * the lock color); every other node is a folder or a file item that may hold endpoints.
     */
    private static final class Dir {
        final String label;
        final boolean host;
        boolean https;
        boolean http;
        final List<Endpoint> endpoints = new ArrayList<>();
        Dir(String label, boolean host) { this.label = label; this.host = host; }
        @Override public String toString() { return label; }
    }

    private final DataStore store;

    private final DefaultMutableTreeNode root = new DefaultMutableTreeNode(new Dir("Site Map", false));
    private final DefaultTreeModel treeModel = new DefaultTreeModel(root);
    private final JTree tree = new JTree(treeModel);

    private final ItemsModel itemsModel = new ItemsModel();
    private final JTable items = new JTable(itemsModel);
    private final TableRowSorter<ItemsModel> sorter = new TableRowSorter<>(itemsModel);

    private final MessageViewer viewer;

    public SiteMapPanel(DataStore store, MontoyaApi api) {
        this.store = store;
        this.viewer = new MessageViewer(api);
        setLayout(new BorderLayout());

        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);
        tree.setRowHeight(0);   // let each row size to its renderer
        tree.setCellRenderer(new SiteMapTreeRenderer(root, tree.getFont()));
        tree.addTreeSelectionListener(e -> onTreeSelect());

        items.setRowSorter(sorter);
        items.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        items.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        items.setFillsViewportHeight(true);
        int[] widths = {70, 420, 60, 60, 80, 180};
        for (int i = 0; i < widths.length && i < items.getColumnModel().getColumnCount(); i++) {
            items.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        items.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onItemSelect();
            }
        });

        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(items), viewer);
        rightSplit.setResizeWeight(0.35);
        rightSplit.setContinuousLayout(true);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(tree), rightSplit);
        mainSplit.setResizeWeight(0.28);
        mainSplit.setContinuousLayout(true);
        add(mainSplit, BorderLayout.CENTER);
    }

    // ---- Tree selection → populate the items table ----------------------

    private void onTreeSelect() {
        Object sel = tree.getLastSelectedPathComponent();
        List<Endpoint> collected = new ArrayList<>();
        if (sel instanceof DefaultMutableTreeNode n) {
            collectSubtree(n, collected);
        }
        collected.sort((a, b) -> {
            int c = pathOf(a).compareTo(pathOf(b));
            return c != 0 ? c : a.getMethod().compareTo(b.getMethod());
        });
        itemsModel.setRows(collected);
        viewer.show(null);
        viewer.setInfo(collected.isEmpty() ? " " : collected.size() + " item(s)");
    }

    private static void collectSubtree(DefaultMutableTreeNode node, List<Endpoint> out) {
        if (node.getUserObject() instanceof Dir d) {
            out.addAll(d.endpoints);
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            collectSubtree((DefaultMutableTreeNode) node.getChildAt(i), out);
        }
    }

    private void onItemSelect() {
        int viewRow = items.getSelectedRow();
        if (viewRow < 0) {
            viewer.show(null);
            return;
        }
        Endpoint e = itemsModel.rowAt(items.convertRowIndexToModel(viewRow));
        if (e == null) {
            viewer.show(null);
            return;
        }
        viewer.show(e.getMessages());
        viewer.setInfo(e.getMethod() + "  " + e.getNormalizedUrl());
    }

    // ---- Refresh: rebuild tree (preserving expansion & selection) -------

    @Override
    public void refreshData() {
        Set<List<String>> expanded = captureExpanded();
        List<String> selectedPath = capturePath(tree.getSelectionPath());

        root.removeAllChildren();
        for (Endpoint e : store.snapshotEndpoints()) {
            String[] key = hostKey(e);          // {scheme|null, authority}
            DefaultMutableTreeNode hostNode = childDir(root, key[1], true);
            Dir hostDir = (Dir) hostNode.getUserObject();
            if ("https".equals(key[0])) {
                hostDir.https = true;
            } else if ("http".equals(key[0])) {
                hostDir.http = true;
            }

            List<String> segs = splitPath(pathOf(e));
            if (segs.isEmpty()) {
                // Root path: show a "/" file item under the host (as Burp does).
                DefaultMutableTreeNode slash = childDir(hostNode, "/", false);
                ((Dir) slash.getUserObject()).endpoints.add(e);
            } else {
                DefaultMutableTreeNode cur = hostNode;
                for (String seg : segs) {
                    cur = childDir(cur, seg, false);
                }
                ((Dir) cur.getUserObject()).endpoints.add(e);
            }
        }
        treeModel.reload();
        restoreExpanded(expanded);
        restoreSelection(selectedPath);
    }

    /** Returns {@code {scheme|null, authority}} — authority is {@code host[:port]} (default port omitted). */
    private static String[] hostKey(Endpoint e) {
        try {
            URI u = URI.create(e.getNormalizedUrl());
            if (u.getScheme() != null && u.getHost() != null) {
                String scheme = u.getScheme().toLowerCase();
                String auth = u.getHost();
                int port = u.getPort();
                if (port > 0 && !isDefaultPort(scheme, port)) {
                    auth = auth + ":" + port;
                }
                return new String[]{scheme, auth};
            }
        } catch (RuntimeException ignored) {
            // fall through to host-based fallback
        }
        return new String[]{null, hostOf(e)};
    }

    private static boolean isDefaultPort(String scheme, int port) {
        return ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
    }

    /** Host bucket fallback when the normalized URL has no scheme/host (JS/relative links). */
    private static String hostOf(Endpoint e) {
        String h = e.getHost();
        if (h != null && !h.isBlank()) {
            return h;
        }
        String p = e.getPath();
        if (p != null && (p.startsWith("http://") || p.startsWith("https://"))) {
            try {
                URI u = URI.create(p);
                if (u.getHost() != null) {
                    return u.getHost();
                }
            } catch (RuntimeException ignored) {
                // fall through
            }
        }
        return "(relative / JS)";
    }

    /**
     * Clean path for tree grouping/display: strips scheme+authority from absolute-URL "paths" (JS
     * links) and drops any query/fragment, so an item lands under its host rather than re-nesting the
     * domain.
     */
    private static String pathOf(Endpoint e) {
        String p = e.getPath();
        if (p == null || p.isBlank()) {
            return "/";
        }
        if (p.startsWith("http://") || p.startsWith("https://")) {
            try {
                String path = URI.create(p).getPath();
                p = (path == null || path.isEmpty()) ? "/" : path;
            } catch (RuntimeException ignored) {
                // leave p as-is
            }
        } else if (p.startsWith("//")) {
            int slash = p.indexOf('/', 2);
            p = slash >= 0 ? p.substring(slash) : "/";
        }
        int cut = p.length();
        int q = p.indexOf('?');
        if (q >= 0) {
            cut = q;
        }
        int hash = p.indexOf('#');
        if (hash >= 0 && hash < cut) {
            cut = hash;
        }
        p = p.substring(0, cut);
        return p.isEmpty() ? "/" : p;
    }

    private static List<String> splitPath(String path) {
        List<String> out = new ArrayList<>();
        if (path == null) {
            return out;
        }
        for (String seg : path.split("/")) {
            if (!seg.isBlank()) {
                out.add(seg);
            }
        }
        return out;
    }

    private DefaultMutableTreeNode childDir(DefaultMutableTreeNode parent, String label, boolean host) {
        for (int i = 0; i < parent.getChildCount(); i++) {
            DefaultMutableTreeNode c = (DefaultMutableTreeNode) parent.getChildAt(i);
            if (c.getUserObject() instanceof Dir d && d.label.equals(label)) {
                return c;
            }
        }
        DefaultMutableTreeNode created = new DefaultMutableTreeNode(new Dir(label, host));
        parent.add(created);
        return created;
    }

    // ---- Expansion / selection preservation (best effort, by label path) -

    private Set<List<String>> captureExpanded() {
        Set<List<String>> paths = new HashSet<>();
        Enumeration<TreePath> en = tree.getExpandedDescendants(new TreePath(root));
        if (en != null) {
            while (en.hasMoreElements()) {
                paths.add(capturePath(en.nextElement()));
            }
        }
        return paths;
    }

    private void restoreExpanded(Set<List<String>> expanded) {
        if (expanded.isEmpty()) {
            for (int i = 0; i < root.getChildCount(); i++) {
                tree.expandPath(new TreePath(
                        ((DefaultMutableTreeNode) root.getChildAt(i)).getPath()));
            }
            return;
        }
        expandMatching(root, expanded);
    }

    private void expandMatching(DefaultMutableTreeNode node, Set<List<String>> expanded) {
        TreePath tp = new TreePath(node.getPath());
        if (expanded.contains(capturePath(tp))) {
            tree.expandPath(tp);
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            expandMatching((DefaultMutableTreeNode) node.getChildAt(i), expanded);
        }
    }

    private void restoreSelection(List<String> labels) {
        if (labels == null || labels.isEmpty()) {
            return;
        }
        DefaultMutableTreeNode node = findByLabels(root, labels, 1);
        if (node != null) {
            TreePath tp = new TreePath(node.getPath());
            tree.setSelectionPath(tp);
            tree.scrollPathToVisible(tp);
        }
    }

    private DefaultMutableTreeNode findByLabels(DefaultMutableTreeNode node, List<String> labels,
                                                int depth) {
        if (depth >= labels.size()) {
            return node;
        }
        String want = labels.get(depth);
        for (int i = 0; i < node.getChildCount(); i++) {
            DefaultMutableTreeNode c = (DefaultMutableTreeNode) node.getChildAt(i);
            if (c.toString().equals(want)) {
                return findByLabels(c, labels, depth + 1);
            }
        }
        return null;
    }

    private static List<String> capturePath(TreePath tp) {
        List<String> labels = new ArrayList<>();
        if (tp != null) {
            for (Object o : tp.getPath()) {
                labels.add(o.toString());
            }
        }
        return labels;
    }

    // ---- Items table model ----------------------------------------------

    private static final class ItemsModel extends AbstractTableModel {
        private static final String[] COLS =
                {"Method", "Path", "Params", "Status", "Length", "MIME"};
        private List<Endpoint> rows = new ArrayList<>();

        void setRows(List<Endpoint> r) {
            this.rows = r != null ? r : new ArrayList<>();
            fireTableDataChanged();
        }

        Endpoint rowAt(int i) {
            return i >= 0 && i < rows.size() ? rows.get(i) : null;
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }

        @Override public Class<?> getColumnClass(int c) {
            return switch (c) {
                case 2, 3, 4 -> Integer.class;
                default -> String.class;
            };
        }

        @Override public Object getValueAt(int r, int c) {
            Endpoint e = rows.get(r);
            return switch (c) {
                case 0 -> e.getMethod();
                case 1 -> pathOf(e);
                case 2 -> e.getParamCount();
                case 3 -> e.getLastStatusCode();
                case 4 -> bodyLength(e.getMessages());
                case 5 -> shortMime(e.getContentType());
                default -> "";
            };
        }

        private static int bodyLength(HttpRequestResponse rr) {
            if (rr == null) {
                return 0;
            }
            HttpResponse resp = rr.response();
            return resp != null ? resp.body().length() : 0;
        }

        private static String shortMime(String contentType) {
            if (contentType == null || contentType.isBlank()) {
                return "";
            }
            String ct = contentType;
            int semi = ct.indexOf(';');
            if (semi >= 0) {
                ct = ct.substring(0, semi);
            }
            return ct.trim();
        }
    }

    // ---- Tree cell renderer: host lock + folder/file icons --------------

    private static final class SiteMapTreeRenderer extends DefaultTreeCellRenderer {
        private final DefaultMutableTreeNode root;
        private final Font baseFont;
        private final Font hostFont;
        private final Icon lockSecure = new LockIcon(new Color(0x3f, 0xb9, 0x50));   // https: green
        private final Icon lockInsecure = new LockIcon(new Color(0xff, 0x5c, 0x5c)); // http: red
        private final Icon lockUnknown = new LockIcon(new Color(0x8a, 0x93, 0x9e));  // unknown: gray

        SiteMapTreeRenderer(DefaultMutableTreeNode root, Font base) {
            this.root = root;
            this.baseFont = base != null ? base : new Font(Font.SANS_SERIF, Font.PLAIN, 12);
            this.hostFont = baseFont.deriveFont(Font.BOLD, baseFont.getSize2D() + 1f);
        }

        @Override
        public Component getTreeCellRendererComponent(JTree t, Object value, boolean selected,
                boolean expanded, boolean leaf, int row, boolean hasFocus) {
            super.getTreeCellRendererComponent(t, value, selected, expanded, leaf, row, hasFocus);
            boolean isHost = value instanceof DefaultMutableTreeNode n
                    && n.getParent() == root && n.getUserObject() instanceof Dir d && d.host;
            if (isHost) {
                Dir d = (Dir) ((DefaultMutableTreeNode) value).getUserObject();
                setFont(hostFont);
                setIcon(d.https ? lockSecure : d.http ? lockInsecure : lockUnknown);
                setIconTextGap(6);
                setBorder(BorderFactory.createEmptyBorder(4, 2, 4, 6));
            } else {
                setFont(baseFont);
                // keep the default folder/file icon set by super
                setIconTextGap(4);
                setBorder(BorderFactory.createEmptyBorder(1, 2, 1, 6));
            }
            return this;
        }
    }

    /** A small padlock icon painted in a given color (scheme indicator for host rows). */
    private static final class LockIcon implements Icon {
        private static final int W = 12;
        private static final int H = 15;
        private final Color color;

        LockIcon(Color color) { this.color = color; }

        @Override public int getIconWidth() { return W; }
        @Override public int getIconHeight() { return H; }

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(color);
            // Shackle (open arc on top).
            g2.setStroke(new java.awt.BasicStroke(1.6f));
            int shackleW = 7;
            int shackleX = x + (W - shackleW) / 2;
            g2.drawArc(shackleX, y + 1, shackleW, 8, 0, 180);
            // Body.
            int bodyW = 10;
            int bodyH = 7;
            int bodyX = x + (W - bodyW) / 2;
            int bodyY = y + H - bodyH;
            g2.fillRoundRect(bodyX, bodyY, bodyW, bodyH, 3, 3);
            // Keyhole.
            g2.setColor(new Color(255, 255, 255, 200));
            g2.fillOval(bodyX + bodyW / 2 - 1, bodyY + 2, 2, 2);
            g2.dispose();
        }
    }
}
