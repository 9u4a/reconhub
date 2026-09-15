package com.reconhub.ui;

import com.reconhub.core.DataStore;
import com.reconhub.model.Endpoint;
import com.reconhub.model.Finding;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTree;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.net.URI;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Summary dashboard: headline stat cards, findings-by-severity chips, Top-hosts chart, and a
 *  collapsible host&rarr;path directory tree of the collected endpoints. */
public final class DashboardPanel extends JPanel implements Refreshable {

    private static final Color ACCENT = new Color(0x4da3ff);
    private static final Map<Finding.Severity, Color> SEV_COLORS = new EnumMap<>(Finding.Severity.class);
    static {
        SEV_COLORS.put(Finding.Severity.HIGH, new Color(0xff5c5c));
        SEV_COLORS.put(Finding.Severity.MEDIUM, new Color(0xffb020));
        SEV_COLORS.put(Finding.Severity.LOW, new Color(0x4da3ff));
        SEV_COLORS.put(Finding.Severity.INFO, new Color(0x7a8698));
    }

    private final DataStore store;

    private final JLabel requests = stat();
    private final JLabel endpoints = stat();
    private final JLabel parameters = stat();
    private final JLabel findings = stat();
    private final JLabel jsFiles = stat();
    private final JLabel hosts = stat();

    private final JPanel severityRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
    private final BarChartPanel hostChart = new BarChartPanel("Top hosts", 10, ACCENT);

    private final DefaultMutableTreeNode root = new DefaultMutableTreeNode("Endpoints");
    private final DefaultTreeModel treeModel = new DefaultTreeModel(root);
    private final JTree tree = new JTree(treeModel);

    public DashboardPanel(DataStore store) {
        this.store = store;
        setLayout(new BorderLayout(0, 10));
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));

        JPanel cards = new JPanel(new GridLayout(1, 6, 10, 10));
        cards.add(card("Requests", requests));
        cards.add(card("Endpoints", endpoints));
        cards.add(card("Parameters", parameters));
        cards.add(card("Findings", findings));
        cards.add(card("JS files", jsFiles));
        cards.add(card("Hosts", hosts));
        cards.setAlignmentX(LEFT_ALIGNMENT);
        north.add(cards);

        severityRow.setAlignmentX(LEFT_ALIGNMENT);
        north.add(severityRow);
        add(north, BorderLayout.NORTH);

        tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);

        JScrollPane treeScroll = new JScrollPane(tree);
        treeScroll.setBorder(BorderFactory.createTitledBorder("Endpoints (directory)"));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, hostChart, treeScroll);
        split.setResizeWeight(0.35);
        split.setContinuousLayout(true);
        add(split, BorderLayout.CENTER);
    }

    private static JLabel stat() {
        JLabel l = new JLabel("0");
        l.setFont(l.getFont().deriveFont(Font.BOLD, 26f));
        return l;
    }

    private JPanel card(String title, JLabel value) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x2a313b)),
                BorderFactory.createEmptyBorder(10, 14, 10, 14)));
        p.setPreferredSize(new Dimension(150, 76));
        JLabel t = new JLabel(title.toUpperCase());
        t.setFont(t.getFont().deriveFont(11f));
        t.setForeground(new Color(0x9aa4b2));
        p.add(value);
        p.add(t);
        return p;
    }

    private static JLabel severityChip(Finding.Severity sev, int count) {
        JLabel l = new JLabel(sev.name() + "  " + count);
        Color c = SEV_COLORS.get(sev);
        l.setOpaque(true);
        l.setBackground(new Color(c.getRed(), c.getGreen(), c.getBlue(), 38));
        l.setForeground(c);
        l.setFont(l.getFont().deriveFont(Font.BOLD, 12f));
        l.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(c, 1, true),
                BorderFactory.createEmptyBorder(3, 10, 3, 10)));
        return l;
    }

    @Override
    public void refreshData() {
        requests.setText(String.valueOf(store.getRequestsProcessed()));
        endpoints.setText(String.valueOf(store.snapshotEndpoints().size()));
        parameters.setText(String.valueOf(store.snapshotParameters().size()));
        findings.setText(String.valueOf(store.snapshotFindings().size()));
        jsFiles.setText(String.valueOf(store.snapshotJsAssets().size()));
        hosts.setText(String.valueOf(store.snapshotTech().size()));

        Map<Finding.Severity, Integer> sevCounts = new EnumMap<>(Finding.Severity.class);
        for (Finding f : store.snapshotFindings()) {
            sevCounts.merge(f.getSeverity(), 1, Integer::sum);
        }
        severityRow.removeAll();
        severityRow.add(new JLabel("Findings by severity:"));
        for (Finding.Severity sev : Finding.Severity.values()) {
            severityRow.add(severityChip(sev, sevCounts.getOrDefault(sev, 0)));
        }
        severityRow.revalidate();
        severityRow.repaint();

        hostChart.setData(store.hostCounts());
        rebuildTree();
    }

    // ---- Endpoint directory tree ----------------------------------------

    private void rebuildTree() {
        Set<List<String>> expanded = captureExpanded();
        root.removeAllChildren();
        for (Endpoint e : store.snapshotEndpoints()) {
            DefaultMutableTreeNode cur = childDir(root, hostOf(e));
            for (String seg : splitPath(pathOf(e))) {
                cur = childDir(cur, seg);
            }
            String leaf = e.getMethod()
                    + (e.getLastStatusCode() > 0 ? " (" + e.getLastStatusCode() + ")" : "");
            cur.add(new DefaultMutableTreeNode(leaf, false));   // method row: not a directory
        }
        treeModel.reload();
        restoreExpanded(expanded);
    }

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
        }
        int q = p.indexOf('?');
        if (q >= 0) {
            p = p.substring(0, q);
        }
        return p.isEmpty() ? "/" : p;
    }

    private static List<String> splitPath(String path) {
        List<String> out = new ArrayList<>();
        if (path != null) {
            for (String seg : path.split("/")) {
                if (!seg.isBlank()) {
                    out.add(seg);
                }
            }
        }
        return out;
    }

    /** Finds or creates a directory child with the given label (method rows never match). */
    private static DefaultMutableTreeNode childDir(DefaultMutableTreeNode parent, String label) {
        for (int i = 0; i < parent.getChildCount(); i++) {
            DefaultMutableTreeNode c = (DefaultMutableTreeNode) parent.getChildAt(i);
            if (c.getAllowsChildren() && label.equals(c.getUserObject())) {
                return c;
            }
        }
        DefaultMutableTreeNode created = new DefaultMutableTreeNode(label);   // directory node
        parent.add(created);
        return created;
    }

    // ---- expansion preservation (best effort, by label path) ------------

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
            labels.add(String.valueOf(((DefaultMutableTreeNode) o).getUserObject()));
        }
        return labels;
    }
}
