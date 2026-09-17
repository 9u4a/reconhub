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
 * Exposes each {@link PayloadCheatsheet} set to Burp Intruder as a selectable payload generator, one
 * per parameter class / injection type. Purely passive registration, done once at extension load —
 * Intruder itself only sends traffic when the user runs an attack from its own UI. Mirrors the same
 * pattern used by the sibling InjectScope extension's Intruder integration.
 */
public final class IntruderPayloads {

    private IntruderPayloads() {}

    public static void register(MontoyaApi api, PayloadCheatsheet sheet) {
        for (PayloadCheatsheet.Set set : sheet.allSets()) {
            api.intruder().registerPayloadGeneratorProvider(new Provider(set));
        }
    }

    private static final class Provider implements PayloadGeneratorProvider {
        private final PayloadCheatsheet.Set set;

        Provider(PayloadCheatsheet.Set set) {
            this.set = set;
        }

        @Override
        public String displayName() {
            return "ReconHub: " + set.label();
        }

        @Override
        public PayloadGenerator providePayloadGenerator(AttackConfiguration attackConfiguration) {
            return new Generator(set.payloads());
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
