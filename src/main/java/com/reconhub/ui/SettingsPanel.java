package com.reconhub.ui;

import burp.api.montoya.MontoyaApi;
import com.reconhub.analysis.FindingTaxonomy;
import com.reconhub.analysis.UserRuleStore;
import com.reconhub.core.Bookmarks;
import com.reconhub.core.DataStore;
import com.reconhub.core.Hosts;
import com.reconhub.core.ScopeFilter;
import com.reconhub.model.Finding;
import com.reconhub.model.TechInfo;
import com.reconhub.core.Settings;
import com.reconhub.core.TrafficIngestor;
import com.reconhub.export.HtmlReporter;
import com.reconhub.export.JsonExporter;
import com.reconhub.export.MarkdownReporter;
import com.reconhub.export.ReportOptions;
import com.reconhub.export.SarifExporter;
import com.reconhub.export.StateSerializer;
import com.reconhub.export.WordlistExporter;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/** Configuration + actions: scope, JS saving, ingest/clear, and JSON/HTML export. */
public final class SettingsPanel extends JPanel {

    private final MontoyaApi api;
    private final DataStore store;
    private final Settings settings;
    private final TrafficIngestor ingestor;
    private final Bookmarks bookmarks;

    private final JLabel status = new JLabel(" ");
    private final JTextField jsDir = new JTextField(36);
    private final JButton ingestButton = new JButton("Ingest Site Map");
    private final JButton cancelButton = new JButton("Cancel");
    private final JProgressBar progress = new JProgressBar();
    private final JCheckBox includeMessages =
            new JCheckBox("Include raw request/response (larger file, keeps viewer/body-search)", true);
    // Report scope (applies to HTML & Markdown export).
    private final JCheckBox reportConfirmedOnly = new JCheckBox("Confirmed only", false);
    private final JCheckBox reportExcludeFp = new JCheckBox("Exclude false positives", false);
    private final JCheckBox reportBookmarkedOnly = new JCheckBox("Bookmarked only", false);

    private final RulesModel rulesModel = new RulesModel();
    private JTable rulesTableRef;

    public SettingsPanel(MontoyaApi api, DataStore store, Settings settings,
                         TrafficIngestor ingestor, Bookmarks bookmarks) {
        this.api = api;
        this.store = store;
        this.settings = settings;
        this.ingestor = ingestor;
        this.bookmarks = bookmarks;

        // 0.64.0: a fixed top bar (ingest + progress + status) over tabs, one per area. Explanations moved
        // into tooltips; every control and its behavior is unchanged.
        setLayout(new java.awt.BorderLayout());
        setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

        JPanel bar = leftFlow();
        bar.add(ingestButton);
        bar.add(progressRow());   // progress + cancel, hidden until an ingest runs
        status.setForeground(SwingColors.MUTED);
        bar.add(status);
        ingestButton.setToolTipText("Re-read Burp's Site Map into ReconHub (passive -- no traffic)");
        ingestButton.addActionListener(e -> doIngest());

        javax.swing.JTabbedPane tabs = new javax.swing.JTabbedPane();
        tabs.addTab("General", pinTop(generalTab()));
        tabs.addTab("JavaScript", pinTop(jsTab()));
        tabs.addTab("Findings", pinTop(findingsTab()));
        tabs.addTab("Match & Replace", pinTop(matchReplaceTab()));
        tabs.addTab("Export & Data", pinTop(exportTab()));
        add(bar, java.awt.BorderLayout.NORTH);
        add(tabs, java.awt.BorderLayout.CENTER);

        rulesModel.reload();
    }

    // ---- tabs -------------------------------------------------------------

    private JPanel generalTab() {
        JPanel t = tabBody();
        t.add(section("Scope"));
        t.add(scopeRow());
        t.add(scopeRegexRow());
        t.add(gap());

        t.add(section("Capture"));
        JCheckBox live = leftCheck("Capture new traffic live", settings.isLiveCaptureEnabled());
        live.addActionListener(e -> settings.setLiveCaptureEnabled(live.isSelected()));
        t.add(live);
        JCheckBox autoIngest = leftCheck("Ingest the site map when the extension loads", settings.isAutoIngestOnLoad());
        autoIngest.addActionListener(e -> settings.setAutoIngestOnLoad(autoIngest.isSelected()));
        t.add(autoIngest);
        JCheckBox ignoreStatic = leftCheck("Skip images, CSS, fonts and media", settings.isIgnoreStaticAssets());
        ignoreStatic.addActionListener(e -> settings.setIgnoreStaticAssets(ignoreStatic.isSelected()));
        t.add(ignoreStatic);
        t.add(gap());

        t.add(section("Analysis"));
        JCheckBox scan = leftCheck("Scan responses for secrets", settings.isScanResponsesForSecrets());
        scan.addActionListener(e -> settings.setScanResponsesForSecrets(scan.isSelected()));
        t.add(scan);
        JCheckBox passive = leftCheck("Passive checks", settings.isRunPassiveChecks());
        passive.setToolTipText("Interesting responses, misconfigurations, comments, request/response leads, JWT checks");
        passive.addActionListener(e -> settings.setRunPassiveChecks(passive.isSelected()));
        t.add(passive);
        t.add(gap());

        t.add(section("Memory"));
        JPanel cap = spinnerRow("Max rows per table (0 = unlimited):", settings.getMaxRetainedItems(),
                0, 1_000_000, 1000, n -> {
                    settings.setMaxRetainedItems(n);
                    store.setMaxRetained(settings.getMaxRetainedItems());   // read back the clamped value
                });
        cap.setToolTipText("Bodies are already kept off the JVM heap. Above the cap the oldest rows leave "
                + "ReconHub's tables (Burp's own history is untouched).");
        t.add(cap);
        return t;
    }

    private JPanel jsTab() {
        JPanel t = tabBody();
        t.add(section("Collected JavaScript"));
        JCheckBox saveJs = leftCheck("Save collected JS to disk", settings.isSaveJsToDisk());
        saveJs.addActionListener(e -> settings.setSaveJsToDisk(saveJs.isSelected()));
        t.add(saveJs);
        t.add(jsDirRow());
        JCheckBox libJs = leftCheck("Analyze library / vendor / third-party JS too (slower, noisier)",
                settings.isAnalyzeLibraryJs());
        libJs.setToolTipText("Off: library JS is still collected and secret-scanned, but skips endpoint "
                + "extraction and deep analysis. Applies to JS ingested after the change.");
        libJs.addActionListener(e -> settings.setAnalyzeLibraryJs(libJs.isSelected()));
        t.add(libJs);
        return t;
    }

    private JPanel findingsTab() {
        JPanel t = tabBody();
        JLabel display = section("Findings tab filter");
        display.setToolTipText("View-only: hides rows in the Findings tab, never drops collected data");
        t.add(display);
        t.add(minSeverityRow());
        t.add(categoryMuteRow());
        t.add(gap());

        JLabel custom = section("Custom detection rules");
        custom.setToolTipText("Your regex rules run with the built-in secret scan on new traffic and the next "
                + "ingest. Saved across restarts.");
        t.add(custom);
        t.add(rulesTable());
        t.add(addRuleRow());
        return t;
    }

    private JPanel matchReplaceTab() {
        JPanel t = tabBody();
        JLabel title = section("Match & Replace -- ACTIVE (sends requests)");
        title.setForeground(SwingColors.WARN);
        t.add(title);
        JCheckBox enabled = leftCheck("Enable Match & Replace", settings.isMatchReplaceEnabled());
        enabled.setToolTipText("ReconHub's only traffic-generating feature. Off by default; every run still asks "
                + "for confirmation.");
        enabled.addActionListener(e -> settings.setMatchReplaceEnabled(enabled.isSelected()));
        t.add(enabled);
        t.add(spinnerRow("Delay between requests (ms):", settings.getMatchReplaceDelayMs(),
                0, 60000, 25, settings::setMatchReplaceDelayMs));
        t.add(spinnerRow("Parallel requests:", settings.getMatchReplaceConcurrency(), 1, 10, 1,
                settings::setMatchReplaceConcurrency));
        return t;
    }

    private JPanel exportTab() {
        JPanel t = tabBody();
        t.add(section("Reports"));
        t.add(reportRow());
        t.add(reportOptionsRow());
        t.add(gap());

        t.add(section("Wordlists (ffuf / Intruder)"));
        t.add(wordlistRow());
        t.add(gap());

        t.add(section("Backup"));
        includeMessages.setText("Include raw requests/responses");
        includeMessages.setToolTipText("Larger file; keeps the viewer and body search working after import");
        includeMessages.setAlignmentX(Component.LEFT_ALIGNMENT);
        t.add(includeMessages);
        t.add(stateRow());
        t.add(gap());

        t.add(section("Data"));
        t.add(dataRow());
        return t;
    }

    /** Keeps a tab's rows at their natural height at the top; spare space stays below them. */
    private static JPanel pinTop(JPanel body) {
        JPanel holder = new JPanel(new java.awt.BorderLayout());
        holder.add(body, java.awt.BorderLayout.NORTH);
        return holder;
    }

    private static JPanel tabBody() {
        JPanel t = new JPanel();
        t.setLayout(new BoxLayout(t, BoxLayout.Y_AXIS));
        t.setBorder(BorderFactory.createEmptyBorder(6, 8, 8, 8));
        return t;
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

    private JPanel scopeRegexRow() {
        JPanel p = leftFlow();
        JTextField include = new JTextField(settings.getScopeIncludeRegex(), 20);
        JTextField exclude = new JTextField(settings.getScopeExcludeRegex(), 20);
        JButton apply = new JButton("Apply");
        apply.addActionListener(e -> {
            String inc = include.getText().trim();
            String exc = exclude.getText().trim();
            String err = validateRegex("Include", inc);
            if (err == null) {
                err = validateRegex("Exclude", exc);
            }
            if (err != null) {
                // Do NOT save: ScopeFilter.compile() treats an uncompilable include regex as "no
                // include filter", which silently WIDENS scope to everything instead of narrowing it.
                // Leave the previous (working) value in effect, same as UserRuleStore.add does for a
                // bad custom rule.
                setStatus(err);
                return;
            }
            settings.setScopeIncludeRegex(inc);
            settings.setScopeExcludeRegex(exc);
            setStatus("Scope regex applied.");
        });
        p.add(new JLabel("Include regex:"));
        p.add(include);
        p.add(new JLabel("Exclude regex:"));
        p.add(exclude);
        p.add(apply);
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

    private JPanel reportRow() {
        JPanel p = leftFlow();
        JButton json = new JButton("JSON…");
        json.addActionListener(e -> exportJson());
        JButton html = new JButton("HTML…");
        html.addActionListener(e -> exportHtml());
        JButton md = new JButton("Markdown…");
        md.addActionListener(e -> exportMarkdown());
        JButton sarif = new JButton("SARIF…");
        sarif.setToolTipText("SARIF 2.1.0 for CI / code scanning");
        sarif.addActionListener(e -> exportSarif());
        p.add(json);
        p.add(html);
        p.add(md);
        p.add(sarif);
        return p;
    }

    private JPanel reportOptionsRow() {
        JPanel p = leftFlow();
        reportConfirmedOnly.setToolTipText("Include only Confirmed findings");
        reportExcludeFp.setToolTipText("Drop findings marked False positive");
        reportBookmarkedOnly.setToolTipText("Include only bookmarked rows, in every section");
        p.add(new JLabel("Include:"));
        p.add(reportConfirmedOnly);
        p.add(reportExcludeFp);
        p.add(reportBookmarkedOnly);
        return p;
    }

    private JPanel dataRow() {
        JPanel p = leftFlow();
        JButton clear = new JButton("Clear data");
        clear.setToolTipText("Empty ReconHub's tables (Burp's own history is untouched)");
        clear.addActionListener(e -> doClear());
        JButton removeOutOfScope = new JButton("Remove out-of-scope hosts…");
        removeOutOfScope.setToolTipText("Delete data for every host the current scope rejects "
                + "(nothing is out of scope with \"All traffic\")");
        removeOutOfScope.addActionListener(e -> doRemoveOutOfScope());
        p.add(clear);
        p.add(removeOutOfScope);
        return p;
    }

    private ReportOptions reportOptions() {
        return new ReportOptions(reportConfirmedOnly.isSelected(), reportExcludeFp.isSelected(),
                reportBookmarkedOnly.isSelected(), bookmarks);
    }

    private JPanel minSeverityRow() {
        JPanel p = leftFlow();
        p.add(new JLabel("Minimum severity:"));
        JComboBox<Finding.Severity> sev = new JComboBox<>(Finding.Severity.values());
        sev.setSelectedItem(settings.getMinFindingSeverity());
        sev.setToolTipText("Show findings at or above this severity (INFO = show all)");
        sev.addActionListener(e -> {
            settings.setMinFindingSeverity((Finding.Severity) sev.getSelectedItem());
            store.fireChanged();
        });
        p.add(sev);
        return p;
    }

    private JPanel categoryMuteRow() {
        JPanel p = new JPanel(new java.awt.BorderLayout(8, 0));
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        p.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        JLabel l = new JLabel("Hide categories:");
        l.setVerticalAlignment(JLabel.TOP);
        p.add(l, java.awt.BorderLayout.WEST);
        JPanel grid = new JPanel(new java.awt.GridLayout(0, 4, 12, 0));
        p.add(grid, java.awt.BorderLayout.CENTER);
        for (FindingTaxonomy.Category c : FindingTaxonomy.Category.values()) {
            JCheckBox b = new JCheckBox(c.label(), settings.isCategoryMuted(c));
            b.addActionListener(e -> {
                settings.setCategoryMuted(c, b.isSelected());
                store.fireChanged();
            });
            grid.add(b);
        }
        // Natural size only: an unbounded maximum let the BoxLayout stretch the grid cells far apart.
        p.setMaximumSize(p.getPreferredSize());
        return p;
    }

    private JPanel wordlistRow() {
        JPanel p = leftFlow();
        JButton paths = new JButton("Paths…");
        paths.addActionListener(e -> exportWordlist(WordlistExporter.Kind.PATHS, "reconhub-paths.txt"));
        JButton params = new JButton("Param names…");
        params.addActionListener(e ->
                exportWordlist(WordlistExporter.Kind.PARAM_NAMES, "reconhub-params.txt"));
        JButton hosts = new JButton("Hosts…");
        hosts.addActionListener(e -> exportWordlist(WordlistExporter.Kind.HOSTS, "reconhub-hosts.txt"));
        p.add(paths);
        p.add(params);
        p.add(hosts);
        return p;
    }

    private void exportWordlist(WordlistExporter.Kind kind, String suggestedName) {
        File f = chooseSaveFile(suggestedName);
        if (f == null) {
            return;
        }
        runExport(() -> WordlistExporter.export(store, f.toPath(), kind), f);
    }

    private JPanel progressRow() {
        JPanel p = leftFlow();
        progress.setStringPainted(true);
        progress.setPreferredSize(new Dimension(260, 18));
        progress.setVisible(false);
        cancelButton.setEnabled(false);
        cancelButton.setVisible(false);
        cancelButton.addActionListener(e -> {
            ingestor.requestCancelBulk();
            setStatus("Cancelling ingest…");
        });
        p.add(progress);
        p.add(cancelButton);
        return p;
    }

    private JScrollPane rulesTable() {
        JTable t = new JTable(rulesModel);
        t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        t.setName("rulesTable");
        JScrollPane sp = new JScrollPane(t);
        sp.setAlignmentX(Component.LEFT_ALIGNMENT);
        sp.setPreferredSize(new Dimension(720, 120));
        sp.setMaximumSize(new Dimension(Integer.MAX_VALUE, 140));
        this.rulesTableRef = t;
        return sp;
    }

    private JPanel addRuleRow() {
        JPanel p = leftFlow();
        JTextField name = new JTextField(14);
        JComboBox<String> sev = new JComboBox<>(new String[]{"HIGH", "MEDIUM", "LOW", "INFO"});
        sev.setSelectedItem("MEDIUM");
        JTextField regex = new JTextField(24);
        JButton addBtn = new JButton("Add rule");
        addBtn.addActionListener(e -> {
            String err = ingestor.userRules().add(name.getText(),
                    (String) sev.getSelectedItem(), regex.getText());
            if (err != null) {
                setStatus(err);
            } else {
                name.setText("");
                regex.setText("");
                rulesModel.reload();
                setStatus("Rule added.");
            }
        });
        JButton removeBtn = new JButton("Remove selected");
        removeBtn.addActionListener(e -> {
            int row = rulesTableRef != null ? rulesTableRef.getSelectedRow() : -1;
            if (row >= 0) {
                ingestor.userRules().removeAt(row);
                rulesModel.reload();
                setStatus("Rule removed.");
            }
        });
        p.add(new JLabel("Name:"));
        p.add(name);
        p.add(sev);
        p.add(new JLabel("Regex:"));
        p.add(regex);
        p.add(addBtn);
        p.add(removeBtn);
        return p;
    }

    private JPanel stateRow() {
        JPanel p = leftFlow();
        JButton exp = new JButton("Export State…");
        exp.setToolTipText("Save all collected data to a re-importable backup file");
        exp.addActionListener(e -> exportState());
        JButton imp = new JButton("Import State…");
        imp.setToolTipText("Load data from a previously exported backup file");
        imp.addActionListener(e -> importState());
        p.add(exp);
        p.add(imp);
        return p;
    }

    // ---- Actions --------------------------------------------------------

    private void doIngest() {
        if (ingestor.isBulkRunning()) {
            setStatus("Ingest already running…");
            return;
        }
        ingestButton.setEnabled(false);
        cancelButton.setEnabled(true);
        cancelButton.setVisible(true);
        progress.setVisible(true);
        progress.setIndeterminate(true);
        progress.setString("starting…");
        setStatus("Ingesting site map…");
        ingestor.ingestSiteMapAsync(
                () -> javax.swing.SwingUtilities.invokeLater(() -> {
                    ingestButton.setEnabled(true);
                    cancelButton.setEnabled(false);
                    cancelButton.setVisible(false);
                    progress.setVisible(false);
                    progress.setIndeterminate(false);
                    setStatus("Ingest complete.");
                }),
                (done, total) -> javax.swing.SwingUtilities.invokeLater(() -> {
                    progress.setIndeterminate(false);
                    progress.setMaximum(Math.max(total, 1));
                    progress.setValue(done);
                    progress.setString(done + " / " + total);
                }));
    }

    /**
     * Bulk cleanup for "ingested a whole site map and out-of-scope noise came along" -- scans every
     * host ReconHub has ever recorded against the current {@link ScopeFilter} (Burp scope +
     * include/exclude regex) and, after one confirmation naming every host, removes them all via
     * {@link DataStore#deleteHosts}. A fresh {@link ScopeFilter} is constructed here rather than
     * threading a shared one through the constructor -- it's cheap/stateless enough that {@code
     * ReconHubExtension} and {@code TrafficIngestor} already each build their own independently.
     *
     * <p>0.41.0: both the scheme lookup and the delete used to happen once per host inside this loop
     * ({@code inferScheme} itself re-scans all endpoints on every call, and the old per-host {@code
     * deleteHost} re-scans all 5 collections on every call) -- O(hosts &times; rows) against exactly the
     * scenario this button targets, where both host count and row count are large right after a whole
     * site map was ingested. {@link Hosts#schemesByHost} and {@link DataStore#deleteHosts} each do their
     * respective full scan exactly once instead.
     */
    private void doRemoveOutOfScope() {
        ScopeFilter scopeFilter = new ScopeFilter(api, settings);
        // Union of two sources rather than trusting either alone: hostCounts is bumped for every
        // processed request (core/DataStore.countRequest), and TechInfo is created for every host
        // TechFingerprinter ever sees regardless of content type -- between them this should be the
        // complete set of hosts ReconHub knows about, but there's no cost to being extra sure.
        java.util.Set<String> hosts = new TreeSet<>(store.hostCounts().keySet());
        for (TechInfo t : store.snapshotTech()) {
            hosts.add(t.getHost());
        }
        Map<String, String> schemes = Hosts.schemesByHost(store);
        List<String> outOfScope = new ArrayList<>();
        for (String host : hosts) {
            if (host == null || host.isBlank()) {
                continue;
            }
            String scheme = schemes.getOrDefault(host.toLowerCase(java.util.Locale.ROOT), "https");
            if (!scopeFilter.inScope(scheme + "://" + host)) {
                outOfScope.add(host);
            }
        }
        if (outOfScope.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No out-of-scope hosts found.",
                    "ReconHub", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JList<String> list = new JList<>(outOfScope.toArray(new String[0]));
        JScrollPane listScroll = new JScrollPane(list);
        listScroll.setPreferredSize(new Dimension(320, Math.min(outOfScope.size(), 12) * 18 + 10));
        JPanel message = new JPanel(new java.awt.BorderLayout(0, 8));
        message.add(new JLabel("Delete ALL ReconHub data for " + outOfScope.size()
                + " out-of-scope host(s)? This cannot be undone."), java.awt.BorderLayout.NORTH);
        message.add(listScroll, java.awt.BorderLayout.CENTER);
        int choice = JOptionPane.showConfirmDialog(this, message,
                "ReconHub — remove out-of-scope hosts", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (choice != JOptionPane.OK_OPTION) {
            return;
        }
        DataStore.HostDeleteResult r = store.deleteHosts(new java.util.HashSet<>(outOfScope));
        setStatus("Removed " + outOfScope.size() + " out-of-scope host(s): " + r.endpoints()
                + " endpoints, " + r.parameters() + " parameters, " + r.findings() + " findings, "
                + r.jsAssets() + " JS assets.");
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
        Path p;
        try {
            p = Paths.get(jsDir.getText().trim());
        } catch (RuntimeException e) {
            setStatus("Invalid folder: " + e.getMessage());
            return;
        }
        // Parsing as a Path proves nothing about writability -- probe for real, so "Save JS to disk"
        // can't be silently dead against a read-only/nonexistent/offline directory.
        try {
            java.nio.file.Files.createDirectories(p);
            Path probe = java.nio.file.Files.createTempFile(p, ".reconhub-probe", ".tmp");
            java.nio.file.Files.deleteIfExists(probe);
        } catch (java.io.IOException | RuntimeException e) {
            setStatus("Folder is not writable (not applied): " + p + " — " + e);
            return;   // keep the previous directory in effect
        }
        settings.setJsSaveDirectory(p);
        setStatus("JS folder set to " + p);
    }

    private void exportJson() {
        File f = chooseSaveFile("reconhub-report.json");
        if (f == null) {
            return;
        }
        ReportOptions opts = reportOptions();
        runExport(() -> JsonExporter.export(store, f.toPath(), opts), f);
    }

    private void exportHtml() {
        File f = chooseSaveFile("reconhub-report.html");
        if (f == null) {
            return;
        }
        ReportOptions opts = reportOptions();
        runExport(() -> HtmlReporter.export(store, f.toPath(), opts), f);
    }

    private void exportMarkdown() {
        File f = chooseSaveFile("reconhub-report.md");
        if (f == null) {
            return;
        }
        ReportOptions opts = reportOptions();
        runExport(() -> MarkdownReporter.export(store, f.toPath(), opts), f);
    }

    private void exportSarif() {
        File f = chooseSaveFile("reconhub.sarif");
        if (f == null) {
            return;
        }
        ReportOptions opts = reportOptions();
        runExport(() -> SarifExporter.export(store, f.toPath(), opts), f);
    }

    private void exportState() {
        File f = chooseSaveFile("reconhub-state.json");
        if (f == null) {
            return;
        }
        boolean withMsgs = includeMessages.isSelected();
        runExport(() -> StateSerializer.export(store, f.toPath(), withMsgs, bookmarks), f);
    }

    private void importState() {
        File f = chooseOpenFile();
        if (f == null) {
            return;
        }
        int choice = JOptionPane.showConfirmDialog(this,
                "Clear current data before importing?\n"
                        + "Yes = replace, No = merge into existing data.",
                "Import State", JOptionPane.YES_NO_CANCEL_OPTION);
        if (choice == JOptionPane.CANCEL_OPTION || choice == JOptionPane.CLOSED_OPTION) {
            return;
        }
        boolean clearFirst = choice == JOptionPane.YES_OPTION;
        setStatus("Importing…");
        new javax.swing.SwingWorker<String, Void>() {
            private Exception error;
            @Override protected String doInBackground() {
                try {
                    return StateSerializer.importInto(store, f.toPath(), clearFirst, bookmarks);
                } catch (Exception e) {
                    error = e;
                    return null;
                }
            }
            @Override protected void done() {
                if (error != null) {
                    setStatus("Import failed: " + error.getMessage());
                    api.logging().logToError("ReconHub import failed: " + error);
                } else {
                    String summary = null;
                    try {
                        summary = get();
                    } catch (Exception ignored) {
                        // fall through
                    }
                    setStatus(summary != null ? summary : "Import complete.");
                    // 0.58.0: per-file JS notes / structural Leads aren't in the state file -- rebuild
                    // them from the saved JS bodies in the background.
                    final String base = summary != null ? summary : "Import complete.";
                    ingestor.rebuildJsNotesAsync(n -> {
                        if (n > 0) {
                            javax.swing.SwingUtilities.invokeLater(() ->
                                    setStatus(base + "  (JS notes rebuilt for " + n + " file(s))"));
                        }
                    });
                }
            }
        }.execute();
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

    private File chooseOpenFile() {
        JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
        return fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION
                ? fc.getSelectedFile() : null;
    }

    // ---- Layout helpers -------------------------------------------------

    private void setStatus(String s) {
        status.setText(s);
    }

    /** @return null when {@code regex} is blank or compiles, else a user-facing error message.
     * Package-private for headless testing. */
    static String validateRegex(String label, String regex) {
        if (regex.isEmpty()) {
            return null;   // blank = filter not set, which is valid
        }
        try {
            java.util.regex.Pattern.compile(regex);
            return null;
        } catch (java.util.regex.PatternSyntaxException ex) {
            return label + " regex is invalid (not applied): " + ex.getDescription()
                    + " near index " + ex.getIndex();
        }
    }

    /** A prominent, full-width section header: accent title over a separator line. */
    private static JLabel section(String title) {
        JLabel l = new JLabel(title.toUpperCase());
        l.setFont(l.getFont().deriveFont(java.awt.Font.BOLD, 13.5f));
        l.setForeground(SwingColors.ACCENT);
        l.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, SwingColors.line()),
                BorderFactory.createEmptyBorder(8, 0, 5, 0)));
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        // Stretch full width in the Y-axis BoxLayout so the underline spans the panel.
        l.setMaximumSize(new Dimension(Integer.MAX_VALUE, l.getPreferredSize().height));
        return l;
    }

    private static JCheckBox leftCheck(String text, boolean selected) {
        JCheckBox cb = new JCheckBox(text, selected);
        cb.setAlignmentX(Component.LEFT_ALIGNMENT);
        return cb;
    }

    private interface IntSetter { void set(int v); }

    /** A labeled integer spinner row. Match & Replace's throttle and the memory retention cap both use
     * it; {@code MatchReplacePanel} is a plain {@code AbstractTablePanel} with no room for a settings
     * block above its table, so those live here in Settings instead. */
    private static JPanel spinnerRow(String label, int value, int min, int max, int step, IntSetter setter) {
        JPanel p = leftFlow();
        p.add(new JLabel(label));
        javax.swing.JSpinner sp = new javax.swing.JSpinner(
                new javax.swing.SpinnerNumberModel(value, min, max, step));
        sp.addChangeListener(e -> setter.set((Integer) sp.getValue()));
        p.add(sp);
        return p;
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

    // ---- Custom-rules table model ---------------------------------------

    private final class RulesModel extends AbstractTableModel {
        private static final String[] COLS = {"Name", "Severity", "Regex"};
        private List<UserRuleStore.UserRule> rows = List.of();

        void reload() {
            rows = ingestor.userRules().rules();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public boolean isCellEditable(int r, int c) { return false; }

        @Override public Object getValueAt(int r, int c) {
            UserRuleStore.UserRule rule = rows.get(r);
            return switch (c) {
                case 0 -> rule.name;
                case 1 -> rule.severity;
                case 2 -> rule.regex;
                default -> "";
            };
        }
    }
}
