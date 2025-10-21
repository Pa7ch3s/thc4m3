package com.jb.thickclient;

import burp.*;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * THC4M3 — Thick Client Helper for Burp
 * - Safe startup (tab always shows; errors go to Extender Output)
 * - Filters: Host (regex), Ports (CSV), MIME (regex)
 * - Events table with labels/comments added to messages
 * - PAC generator (copies PAC to clipboard and shows it)
 * - Checklist sub-tab with Save/Load/Export (via ChecklistPanel)
 */
public final class BurpExtender implements IBurpExtender, ITab, IHttpListener, IProxyListener {

    // ---------- Burp handles ----------
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // ---------- UI ----------
    private JPanel root;
    private JTextField hostRegexField;
    private JTextField portCsvField;
    private JTextField mimeRegexField;
    private JCheckBox onlyMatchChk;
    private DefaultTableModel eventsModel;

    // Tabs
    private JTabbedPane tabs;

    // ---------- Filters (compiled) ----------
    private Pattern hostPattern = Pattern.compile(".*");
    private Pattern mimePattern = Pattern.compile("^(application/json|application/xml|text/.*|application/octet-stream)$");
    private Set<Integer> allowedPorts = new HashSet<>(Arrays.asList(80, 443, 8080, 8443));

    // ---------- Settings keys ----------
    private static final String K_HOST   = "thc4m3.hostRegex";
    private static final String K_PORTS  = "thc4m3.portCsv";
    private static final String K_MIME   = "thc4m3.mimeRegex";
    private static final String K_ONLY   = "thc4m3.onlyMatch";

    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("HH:mm:ss");

    // =============================================================================================
    //  IBurpExtender
    // =============================================================================================
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("THC4M3");

        // Build UI + tab first so a later failure doesn't hide the tab.
        try {
            initUI();
            callbacks.addSuiteTab(this);
        } catch (Throwable t) {
            callbacks.printError("THC4M3: UI init failed: " + t);
        }

        // Wire listeners + settings in a separate try/catch for safety.
        try {
            restoreSettings();
            callbacks.registerHttpListener(this);
            callbacks.registerProxyListener(this);
            info("Loaded. Set allow-lists, then optional PAC.");
        } catch (Throwable t) {
            callbacks.printError("THC4M3: Listener/bootstrap failed: " + t);
            warn("Some listeners failed; see Extender → Errors.");
        }
    }

    // =============================================================================================
    //  ITab
    // =============================================================================================
    @Override public String getTabCaption() { return "THC4M3"; }
    @Override public Component getUiComponent() { return root; }

    // =============================================================================================
    //  IHttpListener / IProxyListener
    // =============================================================================================
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        try {
            IHttpService svc = messageInfo.getHttpService();
            if (svc == null) return;

            boolean hostOk = hostAllowed(svc);
            boolean portOk = portAllowed(svc);

            if (messageIsRequest) {
                if (hostOk && portOk) {
                    // Add a soft tag/comment to help triage in Proxy history
                    messageInfo.setComment("[TCB] host/port match");
                    addEvent("→", svc.getHost(), svc.getPort(), httpMethodOf(messageInfo.getRequest()), "labeled");
                } else if (!onlyMatchChk.isSelected()) {
                    addEvent("→", "-", "-", httpMethodOf(messageInfo.getRequest()), "skipped");
                }
            } else {
                if (hostOk && portOk && responseMimeAllowed(messageInfo)) {
                    IResponseInfo ri = helpers.analyzeResponse(messageInfo.getResponse());
                    messageInfo.setComment("[TCB] mime match: " + mimeFrom(ri));
                    addEvent("←", svc.getHost(), svc.getPort(), String.valueOf(ri.getStatusCode()), "labeled");
                } else if (!onlyMatchChk.isSelected()) {
                    IResponseInfo ri = helpers.analyzeResponse(messageInfo.getResponse());
                    addEvent("←", "-", "-", ri == null ? "-" : String.valueOf(ri.getStatusCode()), "skipped");
                }
            }
        } catch (Throwable t) {
            callbacks.printError("THC4M3 processHttpMessage error: " + t);
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        // No-op for now; all work happens in processHttpMessage.
    }

    // =============================================================================================
    //  UI
    // =============================================================================================
    private void initUI() {
        root = new JPanel(new BorderLayout(8, 8));
        root.setBorder(new EmptyBorder(6, 6, 6, 6));

        JPanel controls = new JPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(3, 3, 3, 3);
        gc.fill = GridBagConstraints.HORIZONTAL;
        gc.weightx = 0;

        int r = 0;

        // Host allow (regex)
        gc.gridx = 0; gc.gridy = r; controls.add(new JLabel("Host allow (regex)"), gc);
        hostRegexField = new JTextField(".*(api|login|auth|gateway).*|localhost|127\\.0\\.0\\.1");
        gc.gridx = 1; gc.gridy = r; gc.weightx = 1; controls.add(hostRegexField, gc);

        JButton quick = new JButton("Quick Start");
        quick.addActionListener(e -> showQuickStart());
        gc.gridx = 2; gc.gridy = r; gc.weightx = 0; controls.add(quick, gc);
        r++;

        // Port allow (comma)
        gc.gridx = 0; gc.gridy = r; controls.add(new JLabel("Port allow (comma)"), gc);
        portCsvField = new JTextField("80,443,8080,8443");
        gc.gridx = 1; gc.gridy = r; gc.weightx = 1; controls.add(portCsvField, gc);

        JButton pac = new JButton("Generate PAC…");
        pac.addActionListener(e -> onGeneratePac());
        gc.gridx = 2; gc.gridy = r; gc.weightx = 0; controls.add(pac, gc);
        r++;

        // MIME allow (regex)
        gc.gridx = 0; gc.gridy = r; controls.add(new JLabel("MIME allow (regex)"), gc);
        mimeRegexField = new JTextField("^(application/json|application/xml|text/.*|application/octet-stream)$");
        gc.gridx = 1; gc.gridy = r; gc.weightx = 1; controls.add(mimeRegexField, gc);

        JButton apply = new JButton("Apply Filters");
        apply.addActionListener(e -> {
            recompilePatternsAndPorts();
            saveSettings();
            info("Filters applied: host=" + hostRegexField.getText());
        });
        gc.gridx = 2; gc.gridy = r; gc.weightx = 0; controls.add(apply, gc);
        r++;

        // Only matching toggle
        onlyMatchChk = new JCheckBox("Show/annotate only matching traffic");
        gc.gridx = 0; gc.gridy = r; gc.gridwidth = 3; controls.add(onlyMatchChk, gc);
        r++;

        root.add(controls, BorderLayout.NORTH);

        // Tabs (Events + Checklist)
        tabs = new JTabbedPane(JTabbedPane.TOP);

        // Events table
        JTable eventsTable = new JTable(eventsModel = new DefaultTableModel(
                new Object[]{"Time", "Direction", "Host", "Port", "Method/Code", "Label"}, 0) {
            @Override public boolean isCellEditable(int row, int col) { return false; }
        });
        eventsTable.setFillsViewportHeight(true);
        JScrollPane tableScroll = new JScrollPane(eventsTable);

        JPanel events = new JPanel(new BorderLayout());
        events.add(tableScroll, BorderLayout.CENTER);

        JTextArea tips = new JTextArea(
            "Quick Start — THC4M3 (MVP)\n" +
            "1) Point your thick client to Burp (127.0.0.1:8080) or set a PAC.\n" +
            "2) Add host patterns and ports above for your app.\n" +
            "3) Toggle ‘Show/annotate only matching traffic’ to reduce noise.\n" +
            "4) Exercise the app; matching traffic will be labeled [TCB].\n" +
            "Tip: For non-proxy-aware apps, use OS redirection (Proxifier/redsocks/pf)."
        );
        tips.setEditable(false);
        tips.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        tips.setBorder(new EmptyBorder(6, 6, 6, 6));
        events.add(tips, BorderLayout.SOUTH);

        tabs.addTab("Events", events);

        // Checklist sub-tab
        ChecklistPanel checklistPanel = new ChecklistPanel(callbacks);
        tabs.addTab("Checklist", checklistPanel.getPanel());

        root.add(tabs, BorderLayout.CENTER);
    }

    // =============================================================================================
    //  Actions
    // =============================================================================================
    private void onGeneratePac() {
        try {
            recompilePatternsAndPorts(); // make sure hostPattern is current
            String pac = PacBuilder
                    .fromRegex(hostPattern)
                    .withProxy("127.0.0.1:8080")
                    .build();

            // Copy to clipboard
            Toolkit.getDefaultToolkit().getSystemClipboard()
                   .setContents(new StringSelection(pac), null);

            // Show dialog with PAC text
            JTextArea area = new JTextArea(pac);
            area.setEditable(false);
            area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
            JScrollPane sc = new JScrollPane(area);
            sc.setPreferredSize(new Dimension(650, 350));
            JOptionPane.showMessageDialog(root, sc, "PAC generated (copied to clipboard)",
                    JOptionPane.INFORMATION_MESSAGE);
            info("PAC copied to clipboard.");
        } catch (Throwable t) {
            callbacks.printError("THC4M3 PAC generation failed: " + t);
            warn("PAC generation failed; see Extender → Errors.");
        }
    }

    private void showQuickStart() {
        JTextArea area = new JTextArea(
            "Quick Start — THC4M3\n\n" +
            "• Set your app to proxy via 127.0.0.1:8080 (or use ‘Generate PAC…’).\n" +
            "• Enter host regex and allowed ports.\n" +
            "• Optional: narrow MIME types.\n" +
            "• Click ‘Apply Filters’, then exercise the app.\n" +
            "• Matching traffic is labeled [TCB] and shown in the Events tab."
        );
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        area.setBorder(new EmptyBorder(6, 6, 6, 6));
        JOptionPane.showMessageDialog(root, new JScrollPane(area), "THC4M3 Quick Start",
                JOptionPane.INFORMATION_MESSAGE);
    }

    // =============================================================================================
    //  Filters & helpers
    // =============================================================================================
    private void recompilePatternsAndPorts() {
        try {
            hostPattern = Pattern.compile(hostRegexField.getText());
        } catch (Exception e) {
            hostPattern = Pattern.compile(".*");
            warn("Invalid host regex; defaulting to \".*\"");
        }
        try {
            mimePattern = Pattern.compile(mimeRegexField.getText());
        } catch (Exception e) {
            mimePattern = Pattern.compile("^(application/json|application/xml|text/.*|application/octet-stream)$");
            warn("Invalid MIME regex; using default.");
        }
        allowedPorts.clear();
        String csv = portCsvField.getText();
        if (csv != null) {
            for (String s : csv.split(",")) {
                s = s.trim();
                if (s.isEmpty()) continue;
                try { allowedPorts.add(Integer.parseInt(s)); }
                catch (NumberFormatException ignored) { /* skip */ }
            }
        }
        if (allowedPorts.isEmpty()) allowedPorts.addAll(Arrays.asList(80, 443, 8080, 8443));
    }

    private boolean hostAllowed(IHttpService svc) {
        String host = svc.getHost() == null ? "" : svc.getHost();
        return hostPattern.matcher(host).find();
    }

    private boolean portAllowed(IHttpService svc) {
        return allowedPorts.contains(svc.getPort());
    }

    private boolean responseMimeAllowed(IHttpRequestResponse messageInfo) {
        byte[] resp = messageInfo.getResponse();
        if (resp == null) return false;
        IResponseInfo ri = helpers.analyzeResponse(resp);
        String mime = mimeFrom(ri);
        return mimePattern.matcher(mime).find();
    }

    private String mimeFrom(IResponseInfo ri) {
        if (ri == null) return "unknown";
        String m = ri.getStatedMimeType();
        if (m == null || m.isEmpty() || "unknown".equalsIgnoreCase(m)) {
            m = ri.getInferredMimeType();
        }
        return m == null ? "unknown" : m;
    }

    private String httpMethodOf(byte[] request) {
        if (request == null) return "-";
        try {
            IRequestInfo ri = helpers.analyzeRequest(request);
            return ri.getMethod();
        } catch (Throwable t) {
            return "-";
        }
    }

    // =============================================================================================
    //  Settings
    // =============================================================================================
    private void saveSettings() {
        callbacks.saveExtensionSetting(K_HOST, hostRegexField.getText());
        callbacks.saveExtensionSetting(K_PORTS, portCsvField.getText());
        callbacks.saveExtensionSetting(K_MIME, mimeRegexField.getText());
        callbacks.saveExtensionSetting(K_ONLY, Boolean.toString(onlyMatchChk.isSelected()));
    }

    private void restoreSettings() {
        String host = nvl(callbacks.loadExtensionSetting(K_HOST),
                ".*(api|login|auth|gateway).*|localhost|127\\.0\\.0\\.1");
        String ports = nvl(callbacks.loadExtensionSetting(K_PORTS), "80,443,8080,8443");
        String mime = nvl(callbacks.loadExtensionSetting(K_MIME),
                "^(application/json|application/xml|text/.*|application/octet-stream)$");
        boolean only = Boolean.parseBoolean(nvl(callbacks.loadExtensionSetting(K_ONLY), "false"));

        hostRegexField.setText(host);
        portCsvField.setText(ports);
        mimeRegexField.setText(mime);
        onlyMatchChk.setSelected(only);

        recompilePatternsAndPorts();
    }

    private static String nvl(String s, String def) { return (s == null || s.isEmpty()) ? def : s; }

    // =============================================================================================
    //  Events
    // =============================================================================================
    private void addEvent(String dirArrow, Object host, Object port, String methodOrCode, String label) {
        String time = LocalTime.now().format(TS);
        eventsModel.addRow(new Object[]{
                time,
                "info".equals(dirArrow) ? "info" : dirArrow,
                host,
                port,
                methodOrCode,
                label
        });
    }

    private void info(String msg) {
        callbacks.printOutput("THC4M3: " + msg);
        addEvent("info", "-", "-", "-", msg);
    }

    private void warn(String msg) {
        callbacks.printOutput("THC4M3: " + msg);
        addEvent("info", "-", "-", "-", msg);
    }
}
