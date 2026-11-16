package com.reconhub.ui;

import com.reconhub.active.AuthDetector;
import com.reconhub.active.SessionProfiles;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.DefaultCellEditor;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Window;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Create / edit a saved identity (0.60.0). Credentials are a checkbox table (type, name, value, how sure
 * the auto-detection is) -- prefilled from a selected request, or from a request / header block the
 * user pastes from the other account's browser and runs "Detect" on. Values are masked unless "Show
 * values" is ticked. Saved to {@link SessionProfiles} (memory only).
 */
final class SessionEditorDialog {

    private SessionEditorDialog() {}

    private static final class Row {
        boolean use;
        AuthDetector.Kind kind;
        String name;
        String value;
        String confidence;

        Row(boolean use, AuthDetector.Kind kind, String name, String value, String confidence) {
            this.use = use;
            this.kind = kind;
            this.name = name;
            this.value = value;
            this.confidence = confidence;
        }
    }

    /**
     * Opens the editor. {@code initial} = identity being edited (null = new); {@code detected} = parts to
     * prefill (CONFIRMED pre-ticked, LIKELY unticked). Returns the saved identity, or null on cancel.
     */
    static SessionProfiles.Identity open(Component owner, SessionProfiles store, SessionProfiles.Identity initial,
                                         List<AuthDetector.Part> detected, String source) {
        Window w = owner == null ? null : (owner instanceof Window win ? win : SwingUtilities.getWindowAncestor(owner));
        JDialog d = new JDialog(w, initial == null ? "ReconHub — save session" : "ReconHub — edit session",
                java.awt.Dialog.ModalityType.APPLICATION_MODAL);
        List<Row> rows = new ArrayList<>();
        if (initial != null) {
            initial.headers().forEach((k, v) -> rows.add(new Row(true, AuthDetector.Kind.HEADER, k, v, "saved")));
            initial.cookies().forEach((k, v) -> rows.add(new Row(true, AuthDetector.Kind.COOKIE, k, v, "saved")));
        }
        if (detected != null) addDetected(rows, detected);

        JTextField name = new JTextField(initial != null ? initial.name()
                : store.uniqueName(defaultName(detected)), 24);
        JCheckBox show = new JCheckBox("Show values");
        JLabel tokenLabel = new JLabel(" ");
        Model model = new Model(rows, show);
        JTable table = new JTable(model);
        table.setRowHeight(22);
        table.getColumnModel().getColumn(0).setMaxWidth(40);
        table.getColumnModel().getColumn(1).setPreferredWidth(70);
        table.getColumnModel().getColumn(1).setCellEditor(new DefaultCellEditor(
                new JComboBox<>(new String[]{"Header", "Cookie"})));
        table.getColumnModel().getColumn(2).setPreferredWidth(160);
        table.getColumnModel().getColumn(3).setPreferredWidth(320);
        table.getColumnModel().getColumn(4).setPreferredWidth(80);
        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean f,
                                                                     int r, int c) {
                Component comp = super.getTableCellRendererComponent(t, v, sel, f, r, c);
                if (c == 4 && !sel) {
                    comp.setForeground("likely".equals(v) ? SwingColors.MUTED : t.getForeground());
                }
                return comp;
            }
        });
        Runnable refreshToken = () -> {
            List<String> values = new ArrayList<>();
            for (Row r : rows) if (r.use) values.add(r.value);
            AuthDetector.TokenInfo ti = AuthDetector.tokenInfo(values);
            tokenLabel.setText(describe(ti));
        };
        model.addTableModelListener(e -> refreshToken.run());
        show.addActionListener(e -> model.fireTableDataChanged());
        refreshToken.run();

        JTextArea paste = new JTextArea(5, 60);
        paste.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        paste.setToolTipText("Paste a raw request or its header lines (Cookie:, Authorization:, …) from the other "
                + "account's browser, then press Detect");
        JButton detect = new JButton("Detect");
        detect.addActionListener(e -> {
            List<AuthDetector.Part> parts = AuthDetector.detect(AuthDetector.parseHeaderBlock(paste.getText()));
            if (parts.isEmpty()) {
                JOptionPane.showMessageDialog(d, "No auth header or session cookie found in the pasted text.",
                        "ReconHub", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            rows.removeIf(r -> !"saved".equals(r.confidence) || initial == null);
            addDetected(rows, parts);
            if (initial == null && (name.getText().isBlank() || name.getText().startsWith("user"))) {
                name.setText(store.uniqueName(defaultName(parts)));
            }
            model.fireTableDataChanged();
        });

        JButton addRow = new JButton("+ Add");
        addRow.addActionListener(e -> {
            rows.add(new Row(true, AuthDetector.Kind.HEADER, "", "", "manual"));
            model.fireTableDataChanged();
            table.editCellAt(rows.size() - 1, 2);
        });
        JButton removeRow = new JButton("Remove");
        removeRow.addActionListener(e -> {
            int[] sel = table.getSelectedRows();
            for (int i = sel.length - 1; i >= 0; i--) rows.remove(table.convertRowIndexToModel(sel[i]));
            model.fireTableDataChanged();
        });

        JPanel root = new JPanel();
        root.setLayout(new BoxLayout(root, BoxLayout.Y_AXIS));
        root.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
        JPanel nameRow = flow();
        nameRow.add(new JLabel("Name:"));
        nameRow.add(name);
        nameRow.add(Box.createHorizontalStrut(12));
        nameRow.add(tokenLabel);
        root.add(nameRow);
        root.add(left(new JLabel("Credentials to send for this identity (ticked rows). Every other auth header "
                + "and session cookie in a request is removed; other cookies stay as captured.")));
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setPreferredSize(new Dimension(700, 170));
        tableScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        root.add(tableScroll);
        JPanel tableButtons = flow();
        tableButtons.add(addRow);
        tableButtons.add(removeRow);
        tableButtons.add(show);
        root.add(tableButtons);
        root.add(Box.createVerticalStrut(6));
        root.add(left(new JLabel("Or paste from the other account's browser (raw request or header lines):")));
        JScrollPane pasteScroll = new JScrollPane(paste);
        pasteScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
        root.add(pasteScroll);
        JPanel detectRow = flow();
        detectRow.add(detect);
        detectRow.add(new JLabel("Kept in memory only -- never saved to disk, State, or reports."));
        root.add(detectRow);

        SessionProfiles.Identity[] result = new SessionProfiles.Identity[1];
        JButton save = new JButton("Save");
        JButton cancel = new JButton("Cancel");
        save.addActionListener(e -> {
            if (table.isEditing()) table.getCellEditor().stopCellEditing();
            String n = name.getText().trim();
            if (n.isEmpty() || SessionProfiles.isBuiltIn(n)) {
                JOptionPane.showMessageDialog(d, "Choose a name (\"Original\" and \"No auth\" are reserved).",
                        "ReconHub", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (store.get(n) != null && (initial == null || !initial.name().equals(n))) {
                if (JOptionPane.showConfirmDialog(d, "Replace the existing session \"" + n + "\"?", "ReconHub",
                        JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) {
                    return;
                }
            }
            Map<String, String> headers = new LinkedHashMap<>();
            Map<String, String> cookies = new LinkedHashMap<>();
            for (Row r : rows) {
                if (!r.use || r.name == null || r.name.isBlank()) continue;
                (r.kind == AuthDetector.Kind.HEADER ? headers : cookies).put(r.name.trim(), r.value == null ? "" : r.value.trim());
            }
            if (headers.isEmpty() && cookies.isEmpty()) {
                JOptionPane.showMessageDialog(d, "Tick at least one credential.", "ReconHub", JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (initial != null && !initial.name().equals(n)) store.remove(initial.name());
            SessionProfiles.Identity id = new SessionProfiles.Identity(n, headers, cookies,
                    source != null ? source : initial != null ? initial.source() : "manual", System.currentTimeMillis());
            store.put(id);
            result[0] = id;
            d.dispose();
        });
        cancel.addActionListener(e -> d.dispose());
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttons.add(cancel);
        buttons.add(save);

        d.getContentPane().setLayout(new BorderLayout());
        d.getContentPane().add(new JScrollPane(root), BorderLayout.CENTER);
        d.getContentPane().add(buttons, BorderLayout.SOUTH);
        d.getRootPane().setDefaultButton(save);
        d.pack();
        d.setSize(Math.min(d.getWidth(), 820), Math.min(d.getHeight(), 640));
        d.setLocationRelativeTo(w);
        d.setVisible(true);
        return result[0];
    }

    private static void addDetected(List<Row> rows, List<AuthDetector.Part> parts) {
        for (AuthDetector.Part p : parts) {
            rows.removeIf(r -> r.kind == p.kind() && r.name.equalsIgnoreCase(p.name()));
            rows.add(new Row(p.confidence() == AuthDetector.Confidence.CONFIRMED, p.kind(), p.name(), p.value(),
                    p.confidence() == AuthDetector.Confidence.CONFIRMED ? "confirmed" : "likely"));
        }
    }

    /** Default name: the token's subject value (local part of an email), else "user". */
    static String defaultName(List<AuthDetector.Part> parts) {
        if (parts == null) return "user";
        List<String> values = new ArrayList<>();
        for (AuthDetector.Part p : parts) values.add(p.value());
        return defaultName(AuthDetector.tokenInfo(values));
    }

    /** Default name from a token summary: its subject value (email local part), else "user". */
    static String defaultName(AuthDetector.TokenInfo ti) {
        if (ti == null || ti.subject().isEmpty()) return "user";
        String v = ti.subject().substring(ti.subject().indexOf('=') + 1);
        int at = v.indexOf('@');
        if (at > 0) v = v.substring(0, at);
        v = v.replaceAll("[^\\p{L}\\p{N}_.-]", "");
        return v.isEmpty() || v.length() > 24 ? "user" : v;
    }

    /** "sub=alice · expires in 23 min" / "⚠ token expired 5 min ago" / "" for non-JWT credentials. */
    static String describe(AuthDetector.TokenInfo ti) {
        if (ti == null) return " ";
        StringBuilder sb = new StringBuilder();
        if (!ti.subject().isEmpty()) sb.append(ti.subject());
        String exp = expiry(ti);
        if (!exp.isEmpty()) {
            if (sb.length() > 0) sb.append("  ·  ");
            sb.append(exp);
        }
        return sb.length() == 0 ? " " : sb.toString();
    }

    /** "expires in 23 min" / "⚠ token expired 5 min ago" / "" when the token has no exp. */
    static String expiry(AuthDetector.TokenInfo ti) {
        if (ti == null || ti.expEpochSec() <= 0) return "";
        long now = Instant.now().getEpochSecond();
        return ti.expired(now) ? "⚠ token expired " + ago(now - ti.expEpochSec()) + " ago"
                : "expires in " + ago(ti.expEpochSec() - now);
    }

    private static String ago(long secs) {
        Duration d = Duration.ofSeconds(Math.max(0, secs));
        if (d.toDays() > 0) return d.toDays() + " d";
        if (d.toHours() > 0) return d.toHours() + " h";
        if (d.toMinutes() > 0) return d.toMinutes() + " min";
        return d.getSeconds() + " s";
    }

    /** First 6 chars + … + length, e.g. "eyJhbG…(212)". */
    static String mask(String v) {
        if (v == null || v.isEmpty()) return "";
        return v.length() <= 8 ? "•".repeat(v.length()) : v.substring(0, 6) + "…(" + v.length() + ")";
    }

    private static JPanel flow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private static Component left(JComponent c) {
        c.setAlignmentX(Component.LEFT_ALIGNMENT);
        return c;
    }

    private static final class Model extends AbstractTableModel {
        private static final String[] COLS = {"Use", "Type", "Name", "Value", "Detected"};
        private final List<Row> rows;
        private final JCheckBox show;

        Model(List<Row> rows, JCheckBox show) {
            this.rows = rows;
            this.show = show;
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return c != 4 && (c != 3 || show.isSelected()); }

        @Override public Object getValueAt(int r, int c) {
            Row row = rows.get(r);
            return switch (c) {
                case 0 -> row.use;
                case 1 -> row.kind == AuthDetector.Kind.HEADER ? "Header" : "Cookie";
                case 2 -> row.name;
                case 3 -> show.isSelected() ? row.value : mask(row.value);
                default -> row.confidence;
            };
        }

        @Override public void setValueAt(Object v, int r, int c) {
            Row row = rows.get(r);
            switch (c) {
                case 0 -> row.use = Boolean.TRUE.equals(v);
                case 1 -> row.kind = "Cookie".equals(v) ? AuthDetector.Kind.COOKIE : AuthDetector.Kind.HEADER;
                case 2 -> row.name = String.valueOf(v);
                case 3 -> row.value = String.valueOf(v);
                default -> { }
            }
            fireTableRowsUpdated(r, r);
        }
    }
}
