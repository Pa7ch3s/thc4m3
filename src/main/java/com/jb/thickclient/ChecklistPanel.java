package com.jb.thickclient;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * A simple, persistent checklist for thick-client testing.
 * - Save/Load persists via Burp's extension settings.
 * - Export copies a JSON-ish blob to clipboard.
 */
public class ChecklistPanel {
    private static final String SETTINGS_KEY = "thc4m3.checklist";
    private final JPanel root = new JPanel(new BorderLayout());
    private final List<JCheckBox> items = new ArrayList<>();
    private final IBurpExtenderCallbacks cb;

    public ChecklistPanel(IBurpExtenderCallbacks callbacks) {
        this.cb = callbacks;

        JPanel list = new JPanel();
        list.setLayout(new BoxLayout(list, BoxLayout.Y_AXIS));

        addItem(list, "Network path known (proxy/PAC configured)");
        addItem(list, "Auth/login flow exercised");
        addItem(list, "MIME filters tuned for app responses");
        addItem(list, "Certificate pinning handled (if present)");
        addItem(list, "Update check / auto-update probed");
        addItem(list, "IPC/Local endpoints enumerated");
        addItem(list, "File I/O locations identified (cache, logs, secrets)");
        addItem(list, "TLS settings reviewed (versions/ciphers)");
        addItem(list, "Interesting headers observed/annotated");

        JScrollPane scroller = new JScrollPane(list);
        scroller.setBorder(BorderFactory.createEmptyBorder());
        root.add(scroller, BorderLayout.CENTER);

        JPanel btns = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton save = new JButton("Save");
        JButton load = new JButton("Load");
        JButton export = new JButton("Export…");
        btns.add(save); btns.add(load); btns.add(export);
        root.add(btns, BorderLayout.SOUTH);

        save.addActionListener(e -> saveToSettings());
        load.addActionListener(e -> loadFromSettings());
        export.addActionListener(e -> exportToClipboard());

        // Auto-load if present
        loadFromSettings();
    }

    public JPanel getPanel() { // <-- returns JPanel to match your callsite
        return root;
    }

    private void addItem(JPanel list, String label) {
        JCheckBox cbx = new JCheckBox(label);
        cbx.setAlignmentX(Component.LEFT_ALIGNMENT);
        list.add(cbx);
        items.add(cbx);
    }

    private void saveToSettings() {
        Properties p = new Properties();
        for (int i = 0; i < items.size(); i++) {
            p.setProperty("item." + i, Boolean.toString(items.get(i).isSelected()));
        }
        p.setProperty("count", Integer.toString(items.size()));
        cb.saveExtensionSetting(SETTINGS_KEY, toInline(p));
        cb.printOutput("THC4M3: Checklist saved.");
    }

    private void loadFromSettings() {
        String raw = cb.loadExtensionSetting(SETTINGS_KEY);
        if (raw == null || raw.isEmpty()) return;
        Properties p = fromInline(raw);
        int n = Math.min(items.size(), Integer.parseInt(p.getProperty("count", "0")));
        for (int i = 0; i < n; i++) {
            boolean sel = Boolean.parseBoolean(p.getProperty("item." + i, "false"));
            items.get(i).setSelected(sel);
        }
        cb.printOutput("THC4M3: Checklist loaded.");
    }

    private void exportToClipboard() {
        // Simple JSON-ish export for pasting into issues/notes
        StringBuilder json = new StringBuilder();
        json.append("{\"thc4m3_checklist\":[");
        for (int i = 0; i < items.size(); i++) {
            JCheckBox b = items.get(i);
            json.append("{\"item\":\"").append(escape(b.getText()))
                .append("\",\"done\":").append(b.isSelected()).append("}");
            if (i < items.size() - 1) json.append(",");
        }
        json.append("]}");
        Toolkit.getDefaultToolkit().getSystemClipboard()
              .setContents(new StringSelection(json.toString()), null);
        cb.printOutput("THC4M3: Checklist copied to clipboard.");
    }

    // --- tiny props serializer (single-line) ---
    private static String toInline(Properties p) {
        StringBuilder b = new StringBuilder();
        for (String k : p.stringPropertyNames()) {
            b.append(escape(k)).append('=').append(escape(p.getProperty(k))).append(';');
        }
        return b.toString();
    }
    private static Properties fromInline(String s) {
        Properties p = new Properties();
        for (String kv : s.split(";")) {
            if (kv.isEmpty()) continue;
            int eq = kv.indexOf('=');
            if (eq < 0) continue;
            String k = unescape(kv.substring(0, eq));
            String v = unescape(kv.substring(eq + 1));
            p.setProperty(k, v);
        }
        return p;
    }
    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace(";", "\\;").replace("=", "\\=");
    }
    private static String unescape(String s) {
        StringBuilder out = new StringBuilder();
        boolean esc = false;
        for (char c : s.toCharArray()) {
            if (esc) { out.append(c); esc = false; }
            else if (c == '\\') esc = true;
            else out.append(c);
        }
        return out.toString();
    }
}
