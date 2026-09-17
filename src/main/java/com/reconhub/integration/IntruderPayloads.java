package com.reconhub.integration;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.intruder.AttackConfiguration;
import burp.api.montoya.intruder.GeneratedPayload;
import burp.api.montoya.intruder.IntruderInsertionPoint;
import burp.api.montoya.intruder.PayloadGenerator;
import burp.api.montoya.intruder.PayloadGeneratorProvider;
import com.reconhub.analysis.PayloadCheatsheet;

import java.util.List;

/**
 * Exposes each {@link PayloadCheatsheet} set to Burp Intruder as two selectable payload generators —
 * basic and bypass/evasion — per parameter class / injection type. Purely passive registration, done
 * once at extension load; Intruder itself only sends traffic when the user runs an attack. Mirrors the
 * same pattern used by the sibling InjectScope extension's Intruder integration.
 */
public final class IntruderPayloads {

    private IntruderPayloads() {}

    public static void register(MontoyaApi api, PayloadCheatsheet sheet) {
        for (PayloadCheatsheet.Set set : sheet.allSets()) {
            if (!set.basic().isEmpty()) {
                api.intruder().registerPayloadGeneratorProvider(
                        new Provider(set.label(), "", set.basic()));
            }
            if (!set.bypass().isEmpty()) {
                api.intruder().registerPayloadGeneratorProvider(
                        new Provider(set.label(), " (bypass)", set.bypass()));
            }
        }
    }

    private static final class Provider implements PayloadGeneratorProvider {
        private final String label;
        private final String suffix;
        private final List<String> payloads;

        Provider(String label, String suffix, List<String> payloads) {
            this.label = label;
            this.suffix = suffix;
            this.payloads = payloads;
        }

        @Override
        public String displayName() {
            return "ReconHub: " + label + suffix;
        }

        @Override
        public PayloadGenerator providePayloadGenerator(AttackConfiguration attackConfiguration) {
            return new Generator(payloads);
        }
    }

    private static final class Generator implements PayloadGenerator {
        private final List<String> payloads;
        private int index;

        Generator(List<String> payloads) {
            this.payloads = payloads;
        }

        @Override
        public GeneratedPayload generatePayloadFor(IntruderInsertionPoint insertionPoint) {
            if (index >= payloads.size()) {
                return GeneratedPayload.end();
            }
            return GeneratedPayload.payload(payloads.get(index++));
        }
    }
}
