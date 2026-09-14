package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.core.TrafficIngestor;
import com.reconhub.export.HtmlReporter;
import com.reconhub.export.JsonExporter;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

/** Configuration + actions: scope, JS saving, ingest/clear, and JSON/HTML export. */
public final class SettingsPanel extends JPanel {

    private final MontoyaApi api;
    private final DataStore store;
    private final Settings settings;
    private final TrafficIngestor ingestor;

    private final JLabel status = new JLabel(" ");
    private final JTextField jsDir = new JTextField(36);
    private final JButton ingestButton = new JButton("Ingest Site Map");

    public SettingsPanel(MontoyaApi api, DataStore store, Settings settings,
                         TrafficIngestor ingestor) {
        this.api = api;
        this.store = store;
        this.settings = settings;
        this.ingestor = ingestor;

        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));

        add(section("Scope"));
        add(scopeRow());
        add(gap());

        add(section("Analysis"));
        JCheckBox scan = leftCheck("Scan responses for secrets",
                settings.isScanResponsesForSecrets());
        scan.addActionListener(e -> settings.setScanResponsesForSecrets(scan.isSelected()));
        add(scan);
        JCheckBox live = leftCheck("Capture new traffic live", settings.isLiveCaptureEnabled());
        live.addActionListener(e -> settings.setLiveCaptureEnabled(live.isSelected()));
        add(live);
        add(gap());

        add(section("JavaScript collection"));
        JCheckBox saveJs = leftCheck("Save collected JS to disk", settings.isSaveJsToDisk());
        saveJs.addActionListener(e -> settings.setSaveJsToDisk(saveJs.isSelected()));
        add(saveJs);
        add(jsDirRow());
        add(gap());

        add(section("Actions"));
        add(actionsRow());
        add(gap());

        status.setForeground(new java.awt.Color(0x9aa4b2));
        status.setAlignmentX(Component.LEFT_ALIGNMENT);
        add(status);
    }

    private JPanel scopeRow() {
        JPanel p = leftFlow();
        JRadioButton burp = new JRadioButton("Burp suite scope only",
                settings.getScopeMode() == Settings.ScopeMode.BURP_SCOPE);
        JRadioButton all = new JRadioButton("All traffic",
                settings.getScopeMode() == Settings.ScopeMode.ALL);
        ButtonGroup g = new ButtonGroup();
        g.add(burp);
        g.add(all);
        burp.addActionListener(e -> settings.setScopeMode(Settings.ScopeMode.BURP_SCOPE));
        all.addActionListener(e -> settings.setScopeMode(Settings.ScopeMode.ALL));
        p.add(burp);
        p.add(all);
        return p;
    }

    private JPanel jsDirRow() {
        JPanel p = leftFlow();
        jsDir.setText(settings.getJsSaveDirectory().toString());
        JButton browse = new JButton("Browse…");
        browse.addActionListener(e -> chooseDir());
        JButton applyDir = new JButton("Apply");
        applyDir.addActionListener(e -> applyJsDir());
        p.add(new JLabel("Folder:"));
        p.add(jsDir);
        p.add(browse);
        p.add(applyDir);
        return p;
    }

    private JPanel actionsRow() {
        JPanel p = leftFlow();
        ingestButton.addActionListener(e -> doIngest());
        JButton clear = new JButton("Clear data");
        clear.addActionListener(e -> doClear());
        JButton json = new JButton("Export JSON…");
        json.addActionListener(e -> exportJson());
        JButton html = new JButton("Export HTML…");
        html.addActionListener(e -> exportHtml());
        p.add(ingestButton);
        p.add(clear);
        p.add(Box.createHorizontalStrut(16));
        p.add(json);
        p.add(html);
        return p;
    }

    // ---- Actions --------------------------------------------------------

    private void doIngest() {
        if (ingestor.isBulkRunning()) {
            setStatus("Ingest already running…");
            return;
        }
        ingestButton.setEnabled(false);
        setStatus("Ingesting site map…");
        ingestor.ingestSiteMapAsync(() -> javax.swing.SwingUtilities.invokeLater(() -> {
            ingestButton.setEnabled(true);
            setStatus("Ingest complete.");
        }));
    }

    private void doClear() {
        int ok = JOptionPane.showConfirmDialog(this,
                "Clear all collected ReconHub data?", "Confirm",
                JOptionPane.OK_CANCEL_OPTION);
        if (ok == JOptionPane.OK_OPTION) {
            store.clear();
            setStatus("Data cleared.");
        }
    }

    private void chooseDir() {
        JFileChooser fc = new JFileChooser(jsDir.getText());
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            jsDir.setText(fc.getSelectedFile().getAbsolutePath());
            applyJsDir();
        }
    }

    private void applyJsDir() {
        try {
            Path p = Paths.get(jsDir.getText().trim());
            settings.setJsSaveDirectory(p);
            setStatus("JS folder set to " + p);
        } catch (RuntimeException e) {
            setStatus("Invalid folder: " + e.getMessage());
        }
    }

    private void exportJson() {
        File f = chooseSaveFile("reconhub-report.json");
        if (f == null) {
            return;
        }
        runExport(() -> JsonExporter.export(store, f.toPath()), f);
    }

    private void exportHtml() {
        File f = chooseSaveFile("reconhub-report.html");
        if (f == null) {
            return;
        }
        runExport(() -> HtmlReporter.export(store, f.toPath()), f);
    }

    private interface ExportTask {
        void run() throws Exception;
    }

    private void runExport(ExportTask task, File target) {
        setStatus("Exporting…");
        new javax.swing.SwingWorker<Void, Void>() {
            private Exception error;
            @Override protected Void doInBackground() {
                try {
                    task.run();
                } catch (Exception e) {
                    error = e;
                }
                return null;
            }
            @Override protected void done() {
                if (error != null) {
                    setStatus("Export failed: " + error.getMessage());
                    api.logging().logToError("ReconHub export failed: " + error);
                } else {
                    setStatus("Exported to " + target.getAbsolutePath());
                }
            }
        }.execute();
    }

    private File chooseSaveFile(String suggestedName) {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File(System.getProperty("user.home"), suggestedName));
        return fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION
                ? fc.getSelectedFile() : null;
    }

    // ---- Layout helpers -------------------------------------------------

    private void setStatus(String s) {
        status.setText(s);
    }

    private static JLabel section(String title) {
        JLabel l = new JLabel(title);
        l.setFont(l.getFont().deriveFont(java.awt.Font.BOLD, 13f));
        l.setBorder(BorderFactory.createEmptyBorder(4, 0, 6, 0));
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        return l;
    }

    private static JCheckBox leftCheck(String text, boolean selected) {
        JCheckBox cb = new JCheckBox(text, selected);
        cb.setAlignmentX(Component.LEFT_ALIGNMENT);
        return cb;
    }

    private static JPanel leftFlow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        return p;
    }

    private static Component gap() {
        return Box.createVerticalStrut(14);
    }
}
