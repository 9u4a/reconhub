package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;

import javax.swing.BorderFactory;
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
import java.awt.Component;
import java.awt.Font;
import java.net.URI;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Burp-style Site Map: a host → path tree on the left, a table of the requests under the selected
 * tree node on the top-right, and a read-only request/response viewer on the bottom-right. Selecting
 * a tree node lists every endpoint in that branch; selecting a table row shows its captured message.
 */
public final class SiteMapPanel extends JPanel implements Refreshable {

    /** Tree node payload: a display label plus the endpoints attached directly at this node. */
    private static final class Dir {
        final String label;
        final List<Endpoint> endpoints = new ArrayList<>();
        Dir(String label) { this.label = label; }
        @Override public String toString() { return label; }
    }

    private final DataStore store;

    private final DefaultMutableTreeNode root = new DefaultMutableTreeNode(new Dir("Site Map"));
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
        tree.setRowHeight(0);   // let each row size to its renderer (host rows are taller)
        tree.setCellRenderer(new HostEmphasisRenderer(root, tree.getFont()));
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
            int c = a.getPath().compareTo(b.getPath());
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
            DefaultMutableTreeNode cur = childDir(root, hostOf(e));
            for (String seg : splitPath(pathOf(e))) {
                cur = childDir(cur, seg);
            }
            ((Dir) cur.getUserObject()).endpoints.add(e);
        }
        treeModel.reload();
        restoreExpanded(expanded);
        restoreSelection(selectedPath);
    }

    /**
     * Host bucket for the tree. Uses the endpoint's own host; for JS-discovered endpoints whose
     * "path" is an absolute URL, recovers the host from it so same-domain items don't fragment.
     */
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
     * Clean path for tree grouping: strips scheme+authority from absolute-URL "paths" (JS links) and
     * drops any query/fragment, so an item lands under its host rather than re-nesting the domain.
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

    private DefaultMutableTreeNode childDir(DefaultMutableTreeNode parent, String label) {
        for (int i = 0; i < parent.getChildCount(); i++) {
            DefaultMutableTreeNode c = (DefaultMutableTreeNode) parent.getChildAt(i);
            if (c.getUserObject() instanceof Dir d && d.label.equals(label)) {
                return c;
            }
        }
        DefaultMutableTreeNode created = new DefaultMutableTreeNode(new Dir(label));
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

    // ---- Tree cell renderer: host (top-level) rows bold, larger, roomier -

    private static final class HostEmphasisRenderer extends DefaultTreeCellRenderer {
        private final DefaultMutableTreeNode root;
        private final Font baseFont;
        private final Font hostFont;

        HostEmphasisRenderer(DefaultMutableTreeNode root, Font base) {
            this.root = root;
            this.baseFont = base != null ? base : new Font(Font.SANS_SERIF, Font.PLAIN, 12);
            this.hostFont = baseFont.deriveFont(Font.BOLD, baseFont.getSize2D() + 3f);
        }

        @Override
        public Component getTreeCellRendererComponent(JTree t, Object value, boolean selected,
                boolean expanded, boolean leaf, int row, boolean hasFocus) {
            super.getTreeCellRendererComponent(t, value, selected, expanded, leaf, row, hasFocus);
            boolean isHost = value instanceof DefaultMutableTreeNode n && n.getParent() == root;
            setFont(isHost ? hostFont : baseFont);
            // Extra vertical breathing room, more for host rows.
            setBorder(BorderFactory.createEmptyBorder(isHost ? 5 : 2, 2, isHost ? 5 : 2, 6));
            return this;
        }
    }
}
