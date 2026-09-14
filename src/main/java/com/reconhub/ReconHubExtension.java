package com.reconhub;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.reconhub.analysis.PatternRegistry;
import com.reconhub.core.DataStore;
import com.reconhub.core.Settings;
import com.reconhub.core.TrafficIngestor;
import com.reconhub.ui.MainTab;
import com.reconhub.ui.SendToReconHubMenu;

import javax.swing.JComponent;
import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * ReconHub entry point. Wires together the data store, the pattern registry, the traffic ingestor
 * (bulk + live) and the UI, then registers everything with Burp.
 */
public final class ReconHubExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("ReconHub");

        PatternRegistry patterns = PatternRegistry.load();
        for (String err : patterns.loadErrors()) {
            api.logging().logToError("ReconHub pattern load: " + err);
        }
        api.logging().logToOutput("ReconHub: loaded "
                + patterns.secretRules().size() + " secret rules, "
                + patterns.jsLinkRules().size() + " JS-link rules, "
                + patterns.techRules().size() + " tech rules.");

        DataStore store = new DataStore();
        Settings settings = new Settings();
        TrafficIngestor ingestor = new TrafficIngestor(api, store, settings, patterns);

        api.http().registerHttpHandler(ingestor);
        api.userInterface().registerContextMenuItemsProvider(new SendToReconHubMenu(ingestor));

        JComponent tab = buildUi(api, store, settings, ingestor);
        api.userInterface().registerSuiteTab("ReconHub", tab);

        api.extension().registerUnloadingHandler(ingestor::shutdown);

        if (settings.isAutoIngestOnLoad()) {
            ingestor.ingestSiteMapAsync(() ->
                    api.logging().logToOutput("ReconHub: auto-ingest of existing site map complete."));
            api.logging().logToOutput("ReconHub loaded. Auto-ingesting existing site map…");
        } else {
            api.logging().logToOutput("ReconHub loaded. Open the ReconHub tab and click "
                    + "\"Ingest Site Map\" to sweep existing traffic.");
        }
    }

    private static JComponent buildUi(MontoyaApi api, DataStore store, Settings settings,
                                      TrafficIngestor ingestor) {
        AtomicReference<JComponent> ref = new AtomicReference<>();
        Runnable build = () -> ref.set(new MainTab(api, store, settings, ingestor).component());
        if (SwingUtilities.isEventDispatchThread()) {
            build.run();
        } else {
            try {
                SwingUtilities.invokeAndWait(build);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (InvocationTargetException e) {
                api.logging().logToError("ReconHub UI build failed: " + e.getCause());
            }
        }
        return ref.get();
    }
}
