package com.reconhub.ui;

import com.reconhub.active.AuthDetector;
import com.reconhub.active.SessionProfiles;
import com.reconhub.core.DataStore;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.ListCellRenderer;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Left side of the Match &amp; Replace tab (0.60.0): the identities a run can use -- the built-ins
 * (Original, No auth) and saved sessions with their credential names, token subject and expiry.
 * "Find in captured traffic" lists account candidates from ReconHub's captured requests; "+ New" opens
 * the editor (paste-to-detect). Memory only.
 */
final class SessionsPanel extends JPanel {

    private final SessionProfiles sessions;
    private final DefaultListModel<String> model = new DefaultListModel<>();
    private final JList<String> list = new JList<>(model);

    SessionsPanel(SessionProfiles sessions, DataStore store) {
        super(new BorderLayout());
        this.sessions = sessions;
        setPreferredSize(new Dimension(260, 200));
        setMinimumSize(new Dimension(200, 100));

        JLabel title = new JLabel("Sessions");
        title.setFont(title.getFont().deriveFont(Font.BOLD));
        JButton find = new JButton("Find in captured traffic");
        find.setToolTipText("List accounts seen in captured requests (auth headers / session cookies) -- sends nothing");
        find.addActionListener(e -> SessionDiscoveryDialog.open(this, store, sessions));
        JButton add = new JButton("+ New");
        add.setToolTipText("Paste another account's request or headers and detect its credentials");
        add.addActionListener(e -> SessionEditorDialog.open(this, sessions, null, null, "manual"));

        JPanel top = new JPanel();
        top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
        top.setBorder(BorderFactory.createEmptyBorder(6, 8, 4, 8));
        JPanel titleRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        titleRow.add(title);
        top.add(titleRow);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 4));
        buttons.add(find);
        buttons.add(add);
        top.add(buttons);
        javax.swing.JCheckBox keepKeys = new javax.swing.JCheckBox("Keep app API keys", sessions.isKeepAppKeys());
        keepKeys.setToolTipText("X-Api-Key / apikey / X-*-Api-Key headers are the app's key, shared by every user: "
                + "keep them when switching session or removing auth (off = strip them too)");
        keepKeys.addActionListener(e -> sessions.setKeepAppKeys(keepKeys.isSelected()));
        JPanel opts = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        opts.add(keepKeys);
        top.add(opts);
        add(top, BorderLayout.NORTH);

        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setCellRenderer(new Renderer());
        list.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) edit(list.getSelectedValue());
            }
            @Override public void mousePressed(MouseEvent e) { popup(e); }
            @Override public void mouseReleased(MouseEvent e) { popup(e); }
        });
        add(new JScrollPane(list), BorderLayout.CENTER);
        JLabel foot = new JLabel("  Memory only · double-click to edit");
        foot.setForeground(SwingColors.MUTED);
        add(foot, BorderLayout.SOUTH);

        sessions.addListener(() -> SwingUtilities.invokeLater(this::reload));
        reload();
    }

    private void reload() {
        String sel = list.getSelectedValue();
        model.clear();
        model.addElement(SessionProfiles.ORIGINAL);
        model.addElement(SessionProfiles.NO_AUTH);
        for (SessionProfiles.Identity id : sessions.list()) model.addElement(id.name());
        if (sel != null && model.contains(sel)) list.setSelectedValue(sel, false);
    }

    private void edit(String name) {
        SessionProfiles.Identity id = name == null ? null : sessions.get(name);
        if (id != null) SessionEditorDialog.open(this, sessions, id, null, null);
    }

    private void popup(MouseEvent e) {
        if (!e.isPopupTrigger()) return;
        int i = list.locationToIndex(e.getPoint());
        if (i < 0) return;
        list.setSelectedIndex(i);
        String name = model.get(i);
        SessionProfiles.Identity id = sessions.get(name);
        JPopupMenu m = new JPopupMenu();
        JMenuItem edit = new JMenuItem("Edit…");
        edit.setEnabled(id != null);
        edit.addActionListener(a -> edit(name));
        JMenuItem rename = new JMenuItem("Rename…");
        rename.setEnabled(id != null);
        rename.addActionListener(a -> {
            String to = JOptionPane.showInputDialog(this, "New name:", name);
            if (to != null && !sessions.rename(name, to)) {
                JOptionPane.showMessageDialog(this, "That name is taken or reserved.", "ReconHub", JOptionPane.WARNING_MESSAGE);
            }
        });
        JMenuItem dup = new JMenuItem("Duplicate");
        dup.setEnabled(id != null);
        dup.addActionListener(a -> sessions.put(new SessionProfiles.Identity(sessions.uniqueName(name),
                id.headers(), id.cookies(), id.source(), System.currentTimeMillis())));
        JMenuItem del = new JMenuItem("Delete");
        del.setEnabled(id != null);
        del.addActionListener(a -> {
            if (JOptionPane.showConfirmDialog(this, "Delete session \"" + name + "\"?", "ReconHub",
                    JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                sessions.remove(name);
            }
        });
        m.add(edit);
        m.add(rename);
        m.add(dup);
        m.addSeparator();
        m.add(del);
        m.show(list, e.getX(), e.getY());
    }

    /** Two-line cell: name (bold) + credentials / token line. Plain JLabels (Burp's L&F ignores HTML). */
    private final class Renderer extends JPanel implements ListCellRenderer<String> {
        private final JLabel name = new JLabel();
        private final JLabel detail = new JLabel();

        Renderer() {
            super(new GridLayout(2, 1));
            setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
            add(name);
            add(detail);
        }

        @Override
        public Component getListCellRendererComponent(JList<? extends String> l, String value, int index,
                                                      boolean selected, boolean focus) {
            name.setFont(l.getFont().deriveFont(Font.BOLD));
            detail.setFont(l.getFont().deriveFont(l.getFont().getSize2D() - 1f));
            String line;
            boolean warn = false;
            if (SessionProfiles.ORIGINAL.equals(value)) {
                name.setText("● Original (baseline)");
                line = "request exactly as captured";
            } else if (SessionProfiles.NO_AUTH.equals(value)) {
                name.setText("● No auth");
                line = "all cookies and auth headers removed";
            } else {
                SessionProfiles.Identity id = sessions.get(value);
                name.setText("● " + value);
                if (id == null) {
                    line = "";
                } else {
                    AuthDetector.TokenInfo ti = id.tokenInfo();
                    String tok = ti == null ? "" : SessionEditorDialog.describe(ti).trim();
                    warn = ti != null && ti.expired(java.time.Instant.now().getEpochSecond());
                    line = id.summary() + (tok.isEmpty() ? "" : "  ·  " + tok);
                }
            }
            detail.setText(line.isEmpty() ? " " : line);
            setBackground(selected ? l.getSelectionBackground() : l.getBackground());
            name.setForeground(selected ? l.getSelectionForeground() : l.getForeground());
            detail.setForeground(warn ? SwingColors.HIGH : selected ? l.getSelectionForeground() : SwingColors.MUTED);
            setToolTipText(line);
            return this;
        }
    }
}
