package com.reconhub.ui;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A lightweight horizontal bar chart painted directly (no external libraries). Theme-aware: it uses
 * the panel's own fore/background so it fits Burp's light or dark theme. Shows the top-N entries.
 */
public final class BarChartPanel extends JPanel {

    private record Bar(String label, int value) {}

    private final String title;
    private final int topN;
    private final Color accent;
    private List<Bar> bars = new ArrayList<>();
    private int max = 1;

    public BarChartPanel(String title, int topN, Color accent) {
        this.title = title;
        this.topN = topN;
        this.accent = accent;
        setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
    }

    public void setData(Map<?, Integer> data) {
        List<Bar> list = new ArrayList<>();
        int m = 1;
        int i = 0;
        for (Map.Entry<?, Integer> e : data.entrySet()) {
            if (i++ >= topN) {
                break;
            }
            list.add(new Bar(String.valueOf(e.getKey()), e.getValue()));
            m = Math.max(m, e.getValue());
        }
        this.bars = list;
        this.max = m;
        int rows = Math.max(1, list.size());
        setPreferredSize(new Dimension(320, 34 + rows * 26));
        revalidate();
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g0) {
        super.paintComponent(g0);
        Graphics2D g = (Graphics2D) g0.create();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int w = getWidth();
        int pad = 12;
        int y = 8;

        Color fg = getForeground();
        Color muted = blend(fg, getBackground(), 0.45f);

        g.setColor(fg);
        g.setFont(getFont().deriveFont(Font.BOLD, 13f));
        g.drawString(title, pad, y + 12);
        y += 26;

        if (bars.isEmpty()) {
            g.setColor(muted);
            g.setFont(getFont().deriveFont(12f));
            g.drawString("(none)", pad, y + 12);
            g.dispose();
            return;
        }

        int labelW = 150;
        int valueW = 46;
        int barAreaX = pad + labelW + 6;
        int barAreaW = Math.max(20, w - barAreaX - valueW - pad);
        int rowH = 24;

        g.setFont(getFont().deriveFont(12f));
        for (Bar b : bars) {
            int cy = y + rowH / 2;

            g.setColor(muted);
            g.drawString(fit(g, b.label(), labelW), pad, cy + 4);

            int bw = (int) Math.round((double) barAreaW * b.value() / max);
            bw = Math.max(2, bw);
            g.setColor(accent);
            g.fillRoundRect(barAreaX, y + 4, bw, rowH - 10, 6, 6);

            g.setColor(fg);
            g.drawString(String.valueOf(b.value()), barAreaX + bw + 6, cy + 4);

            y += rowH;
        }
        g.dispose();
    }

    private static String fit(Graphics2D g, String s, int maxW) {
        if (g.getFontMetrics().stringWidth(s) <= maxW) {
            return s;
        }
        String ell = "…";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (g.getFontMetrics().stringWidth(sb.toString() + c + ell) > maxW) {
                break;
            }
            sb.append(c);
        }
        return sb + ell;
    }

    private static Color blend(Color a, Color b, float t) {
        return new Color(
                (int) (a.getRed() * (1 - t) + b.getRed() * t),
                (int) (a.getGreen() * (1 - t) + b.getGreen() * t),
                (int) (a.getBlue() * (1 - t) + b.getBlue() * t));
    }
}
