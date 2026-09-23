package com.reconhub.ui;

import org.junit.jupiter.api.Test;

import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.image.BufferedImage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code AbstractTablePanel.ellipsize} -- the field-selector combo's overflow truncation (0.38.2).
 * {@link FontMetrics} can be measured off a throwaway {@link BufferedImage}'s graphics context with no
 * display connection needed, so this is fully headless despite being pixel-width math.
 */
class EllipsisTruncationTest {

    private static final FontMetrics FM =
            new BufferedImage(1, 1, BufferedImage.TYPE_INT_ARGB).createGraphics()
                    .getFontMetrics(new Font(Font.SANS_SERIF, Font.PLAIN, 12));

    @Test
    void textThatAlreadyFitsIsReturnedUnchanged() {
        String text = "Host";
        int wide = FM.stringWidth(text) + 50;
        assertEquals(text, AbstractTablePanel.ellipsize(text, FM, wide));
    }

    @Test
    void textThatFitsExactlyIsReturnedUnchanged() {
        String text = "Host";
        int exact = FM.stringWidth(text);
        assertEquals(text, AbstractTablePanel.ellipsize(text, FM, exact));
    }

    @Test
    void overflowingTextGetsAnEllipsisSuffix() {
        String text = "Missing security headers";
        int tooNarrow = FM.stringWidth("Missing sec");   // deliberately shorter than the full text
        String out = AbstractTablePanel.ellipsize(text, FM, tooNarrow);
        assertTrue(out.endsWith("…"), "truncated text must end with an ellipsis: " + out);
        assertTrue(out.length() < text.length() + 1, "must actually be shorter than the original");
    }

    @Test
    void resultNeverExceedsTheRequestedWidth() {
        String text = "Missing security headers";
        // Below the ellipsis glyph's own width, the documented fallback (just the ellipsis) can itself
        // exceed maxWidth -- that's the function's explicit floor behavior, not a bug, so the loop
        // starts at the ellipsis's own width rather than claiming the invariant holds all the way to 0.
        int floor = FM.stringWidth("…");
        for (int w = floor; w <= FM.stringWidth(text) + 5; w += 3) {
            String out = AbstractTablePanel.ellipsize(text, FM, w);
            assertTrue(FM.stringWidth(out) <= w,
                    "ellipsize(\"" + text + "\", " + w + ") = \"" + out + "\" (" + FM.stringWidth(out)
                            + "px) exceeds the requested width");
        }
    }

    @Test
    void extremelyNarrowWidthFallsBackToJustTheEllipsis() {
        String out = AbstractTablePanel.ellipsize("Missing security headers", FM, 1);
        assertEquals("…", out);
    }

    @Test
    void zeroOrNegativeWidthNeverThrows() {
        assertEquals("…", AbstractTablePanel.ellipsize("Content-Type", FM, 0));
        assertEquals("…", AbstractTablePanel.ellipsize("Content-Type", FM, -10));
    }

    @Test
    void emptyStringIsSafe() {
        assertEquals("", AbstractTablePanel.ellipsize("", FM, 100));
    }

    @Test
    void endpointsReferenceColumnNeverTruncatesAtItsOwnCalibratedWidth() {
        // The exact scenario this feature exists for: FIELD_BOX_WIDTH_REFERENCE ("Content-Type") must
        // never truncate itself once the combo is sized to fit it.
        String reference = "Content-Type";
        int width = FM.stringWidth(reference);
        assertEquals(reference, AbstractTablePanel.ellipsize(reference, FM, width));
    }

    @Test
    void techsLongestColumnActuallyGetsTruncatedAtTheReferenceWidth() {
        // Confirms the motivating case from the user report: Tech's "Missing security headers" is
        // longer than Endpoints' "Content-Type" reference, so at that width it must be shortened.
        String tech = "Missing security headers";
        String reference = "Content-Type";
        int width = FM.stringWidth(reference);
        String out = AbstractTablePanel.ellipsize(tech, FM, width);
        assertTrue(out.length() < tech.length());
        assertTrue(out.endsWith("…"));
    }
}
