package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;

import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JPanel;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Hierarchical Site Map: collected endpoints grouped host → path segments in a {@link JTree}, with a
 * read-only request/response viewer. Selecting an endpoint leaf shows its captured message.
 */
public final class SiteMapPanel extends JPanel implements Refreshable {

    /** Tree node payload: a label plus (for endpoint leaves) the endpoint it represents. */
    private record Node(String label, Endpoint endpoint) {
        @Override public String toString() { return label; }
    }

    private final DataStore store;
    private final DefaultMutableTreeNode root = new DefaultMutableTreeNode(new Node("Site Map", null));
    private final DefaultTreeModel model = new DefaultTreeModel(root);
    private final JTree tree = new JTree(model);
    private final MessageViewer viewer;

    public SiteMapPanel(DataStore store, MontoyaApi api) {
        this.store = store;
        this.viewer = new MessageViewer(api);
        setLayout(new BorderLayout());

        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);
        tree.addTreeSelectionListener(e -> onSelect());

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                new JScrollPane(tree), viewer);
        split.setResizeWeight(0.32);
        split.setContinuousLayout(true);
        add(split, BorderLayout.CENTER);
    }

    private void onSelect() {
        Object sel = tree.getLastSelectedPathComponent();
        if (!(sel instanceof DefaultMutableTreeNode n) || !(n.getUserObject() instanceof Node node)) {
            return;
        }
        if (node.endpoint() != null) {
            viewer.show(node.endpoint().getMessages());
            viewer.setInfo(node.endpoint().getMethod() + "  " + node.endpoint().getNormalizedUrl());
        } else {
            viewer.show(null);
            viewer.setInfo(node.label());
        }
    }

    @Override
    public void refreshData() {
        Set<List<String>> expanded = captureExpanded();

        root.removeAllChildren();
        for (Endpoint e : store.snapshotEndpoints()) {
            String host = e.getHost() == null || e.getHost().isBlank()
                    ? "(relative / JS)" : e.getHost();
            DefaultMutableTreeNode hostNode = childDir(root, host);
            DefaultMutableTreeNode cur = hostNode;
            for (String seg : splitPath(e.getPath())) {
                cur = childDir(cur, seg);
            }
            String leaf = e.getMethod()
                    + (e.getLastStatusCode() > 0 ? " (" + e.getLastStatusCode() + ")" : "");
            cur.add(new DefaultMutableTreeNode(new Node(leaf, e)));
        }
        model.reload();
        restoreExpanded(expanded);
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

    /** Finds or creates a directory child (endpoint == null) with the given label. */
    private DefaultMutableTreeNode childDir(DefaultMutableTreeNode parent, String label) {
        for (int i = 0; i < parent.getChildCount(); i++) {
            DefaultMutableTreeNode c = (DefaultMutableTreeNode) parent.getChildAt(i);
            if (c.getUserObject() instanceof Node n && n.endpoint() == null
                    && n.label().equals(label)) {
                return c;
            }
        }
        DefaultMutableTreeNode created = new DefaultMutableTreeNode(new Node(label, null));
        parent.add(created);
        return created;
    }

    // ---- Expansion preservation (best effort, by label path) ------------

    private Set<List<String>> captureExpanded() {
        Set<List<String>> paths = new HashSet<>();
        Enumeration<TreePath> en = tree.getExpandedDescendants(new TreePath(root));
        if (en != null) {
            while (en.hasMoreElements()) {
                paths.add(labelPath(en.nextElement()));
            }
        }
        return paths;
    }

    private void restoreExpanded(Set<List<String>> expanded) {
        if (expanded.isEmpty()) {
            // First render: expand host level for orientation.
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
        if (expanded.contains(labelPath(tp))) {
            tree.expandPath(tp);
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            expandMatching((DefaultMutableTreeNode) node.getChildAt(i), expanded);
        }
    }

    private static List<String> labelPath(TreePath tp) {
        List<String> labels = new ArrayList<>();
        for (Object o : tp.getPath()) {
            labels.add(o.toString());
        }
        return labels;
    }
}
