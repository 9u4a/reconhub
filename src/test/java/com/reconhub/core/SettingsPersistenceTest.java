package com.reconhub.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@code Settings.save}/{@code load} round-trip through an in-memory preference store (ApiStub). Guards
 * the "every field must be copied in both toDto() and fromDto()" rule the CLAUDE.md warns about -- a
 * field missing from either side silently resets to its default on every save/load cycle. Added with
 * 0.44.0's {@code maxRetainedItems}, which this test specifically pins.
 */
class SettingsPersistenceTest {

    @Test
    void maxRetainedItemsSurvivesSaveLoad() {
        ApiStub stub = new ApiStub();
        Settings s = new Settings();
        s.setMaxRetainedItems(25_000);
        s.save(stub.api);

        Settings loaded = Settings.load(stub.api);
        assertEquals(25_000, loaded.getMaxRetainedItems());
    }

    @Test
    void defaultMaxRetainedIsUnlimitedZero() {
        ApiStub stub = new ApiStub();
        new Settings().save(stub.api);
        assertEquals(0, Settings.load(stub.api).getMaxRetainedItems());
    }

    @Test
    void positiveCapIsFlooredToSaneMinimum() {
        Settings s = new Settings();
        s.setMaxRetainedItems(5);        // below the 1000 floor
        assertEquals(1000, s.getMaxRetainedItems());
        s.setMaxRetainedItems(0);        // 0 stays unlimited
        assertEquals(0, s.getMaxRetainedItems());
    }
}
