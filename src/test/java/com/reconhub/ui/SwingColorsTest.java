package com.reconhub.ui;

import burp.api.montoya.ui.Theme;
import com.reconhub.core.ApiStub;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code SwingColors.isDark()} -- 0.37.0 dark-theme support. Burp's Theme API is poll-only (confirmed
 * via {@code javap} against montoya-api 2023.12.1: {@code UserInterface} has no change-notification
 * callback), so this is the one piece of the theme feature that's pure logic and can be verified
 * headlessly; everything else (actual color legibility) needs a manual Burp smoke test in both themes.
 *
 * <p>Same-package test (SwingColors is package-private by design), and resets {@code SwingColors}'
 * static {@code api} field after each test so this doesn't leak state into other test classes that
 * happen to run in the same JVM/test worker.
 */
class SwingColorsTest {

    @AfterEach
    void resetInit() {
        SwingColors.init(null);
    }

    @Test
    void defaultsToDarkBeforeInit() {
        SwingColors.init(null);
        assertTrue(SwingColors.isDark(), "no api yet -- every color here was originally dark-tuned, so "
                + "dark must stay the safe default");
    }

    @Test
    void reflectsDarkTheme() {
        ApiStub stub = new ApiStub();
        stub.setTheme(Theme.DARK);
        SwingColors.init(stub.api);
        assertTrue(SwingColors.isDark());
    }

    @Test
    void reflectsLightTheme() {
        ApiStub stub = new ApiStub();
        stub.setTheme(Theme.LIGHT);
        SwingColors.init(stub.api);
        assertFalse(SwingColors.isDark());
    }

    @Test
    void picksUpALiveThemeFlip() {
        ApiStub stub = new ApiStub();
        stub.setTheme(Theme.DARK);
        SwingColors.init(stub.api);
        assertTrue(SwingColors.isDark());

        stub.setTheme(Theme.LIGHT);
        assertFalse(SwingColors.isDark(), "isDark() re-polls every call -- no caching to go stale");
    }

    @Test
    void lineAndBannerColorsDifferBetweenThemes() {
        ApiStub stub = new ApiStub();
        SwingColors.init(stub.api);

        stub.setTheme(Theme.DARK);
        var darkLine = SwingColors.line();
        var darkBannerBg = SwingColors.bannerBg();
        var darkBannerFg = SwingColors.bannerFg();

        stub.setTheme(Theme.LIGHT);
        var lightLine = SwingColors.line();
        var lightBannerBg = SwingColors.bannerBg();
        var lightBannerFg = SwingColors.bannerFg();

        // These three were the ones actually confirmed dark-tuned this round (a near-black separator,
        // a near-black-red banner) -- they must have a real, distinct light-theme variant, not just
        // fall through to the same hardcoded value regardless of theme.
        assertFalse(darkLine.equals(lightLine), "line() must differ between themes");
        assertFalse(darkBannerBg.equals(lightBannerBg), "bannerBg() must differ between themes");
        assertFalse(darkBannerFg.equals(lightBannerFg), "bannerFg() must differ between themes");
    }

    // ---- blend()/stripe() -- the zebra-striping math (0.37.0) --------------------------------------

    @Test
    void blendZeroReturnsBaseUnchanged() {
        Color base = new Color(0x1e1e1e);
        assertEquals(base, SwingColors.blend(base, Color.WHITE, 0.0));
    }

    @Test
    void blendOneReturnsTowardUnchanged() {
        Color toward = new Color(0x9aa4b2);
        assertEquals(toward, SwingColors.blend(Color.BLACK, toward, 1.0));
    }

    @Test
    void blendHalfwayIsTheAverage() {
        Color base = new Color(0, 0, 0);
        Color toward = new Color(200, 100, 50);
        Color mid = SwingColors.blend(base, toward, 0.5);
        assertEquals(100, mid.getRed());
        assertEquals(50, mid.getGreen());
        assertEquals(25, mid.getBlue());
    }

    @Test
    void stripeAlwaysDiffersFromTheBaseBackground() {
        // Must produce a visibly different (if subtle) color from both a typical dark and a typical
        // light table background -- a striped renderer that computed the same color back would be a
        // silent no-op bug (nothing would actually stripe).
        assertNotEquals(new Color(0x1e1e1e), SwingColors.stripe(new Color(0x1e1e1e)));
        assertNotEquals(Color.WHITE, SwingColors.stripe(Color.WHITE));
    }

    @Test
    void stripeMovesTowardMutedNotAwayFromIt() {
        Color darkBg = new Color(0x1e1e1e);
        Color striped = SwingColors.stripe(darkBg);
        // MUTED (0x9aa4b2) is lighter than a typical dark background -- striping a dark background
        // should lighten it slightly, not darken it further.
        assertTrue(striped.getRed() > darkBg.getRed());
        assertTrue(striped.getGreen() > darkBg.getGreen());
        assertTrue(striped.getBlue() > darkBg.getBlue());
    }
}
