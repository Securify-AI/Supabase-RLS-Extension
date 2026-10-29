/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Main UI panel
 */

package com.supabase.rlsscanner.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.supabase.rlsscanner.core.InstanceStore;
import com.supabase.rlsscanner.core.ScannerConfig;
import com.supabase.rlsscanner.models.ScanResult;
import com.supabase.rlsscanner.models.SupabaseInstance;
import com.supabase.rlsscanner.scanner.ActiveScanner;
import com.supabase.rlsscanner.scanner.PassiveScanner;
import com.supabase.rlsscanner.scanner.SupabaseScanCheck;
import com.supabase.rlsscanner.utils.ReportExporter;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Main UI panel for the Supabase RLS Scanner extension.
 */
public class ScannerPanel extends JPanel {
    
    private final MontoyaApi api;
    private final Logging logging;
    private final ScannerConfig config;
    private final InstanceStore instanceStore;
    private final ActiveScanner activeScanner;
    private final SupabaseScanCheck scanCheck;
    private final PassiveScanner passiveScanner;

    // UI Components
    private InstanceTableModel instanceTableModel;
    private VulnerableTableModel vulnerableTableModel;
    private JTable instanceTable;
    private JTable vulnerableTable;
    private JTextArea statusArea;
    private JCheckBox passiveScanCheckbox;
    private JCheckBox activeScanCheckbox;
    private JCheckBox autoEnumerateCheckbox;
    private JButton scanButton;
    private JButton clearButton;
    private JProgressBar progressBar;

    // Thread pool for background scanning
    private final ExecutorService executor;

    public ScannerPanel(MontoyaApi api, ScannerConfig config,
                        InstanceStore instanceStore, ActiveScanner activeScanner,
                        SupabaseScanCheck scanCheck) {
        this(api, config, instanceStore, activeScanner, scanCheck, null);
    }

    public ScannerPanel(MontoyaApi api, ScannerConfig config,
                        InstanceStore instanceStore, ActiveScanner activeScanner,
                        PassiveScanner passiveScanner) {
        this(api, config, instanceStore, activeScanner, null, passiveScanner);
    }

    public ScannerPanel(MontoyaApi api, ScannerConfig config,
                        InstanceStore instanceStore, ActiveScanner activeScanner,
                        SupabaseScanCheck scanCheck, PassiveScanner passiveScanner) {
        this.api = api;
        this.logging = api.logging();
        this.config = config;
        this.instanceStore = instanceStore;
        this.activeScanner = activeScanner;
        this.scanCheck = scanCheck;
        this.passiveScanner = passiveScanner;
        this.executor = Executors.newSingleThreadExecutor();

        initializeUI();
        setupListeners();

        // Wire up status listener for ActiveScanner
        activeScanner.setStatusListener(message ->
            SwingUtilities.invokeLater(() -> logStatus(message))
        );

        // Log disclaimer notice to status area on startup
        logDisclaimerToStatus();
    }

    /**
     * Log the disclaimer notice to the status area.
     */
    private void logDisclaimerToStatus() {
        SwingUtilities.invokeLater(() -> {
            statusArea.append("========================================\n");
            statusArea.append("!! IMPORTANT NOTICE !!\n");
            statusArea.append("========================================\n");
            statusArea.append("This tool provides basic security checks\n");
            statusArea.append("only - not suitable for production apps.\n");
            statusArea.append("\n");
            statusArea.append("For comprehensive security audits,\n");
            statusArea.append("compliance reviews, threat modeling, and\n");
            statusArea.append("production readiness validation, reach\n");
            statusArea.append("out to Securify AI for one complimentary\n");
            statusArea.append("consultation: contact@securifyai.co\n");
            statusArea.append("========================================\n\n");
        });
    }
    
    private void initializeUI() {
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Create main split pane
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.5);
        
        // Top panel: Discovered instances
        JPanel topPanel = createInstancesPanel();
        mainSplit.setTopComponent(topPanel);
        
        // Bottom panel: Vulnerable tables + Status
        JPanel bottomPanel = createBottomPanel();
        mainSplit.setBottomComponent(bottomPanel);
        
        add(mainSplit, BorderLayout.CENTER);
        
        // Right panel: Configuration
        JPanel configPanel = createConfigPanel();
        add(configPanel, BorderLayout.EAST);
    }
    
    private JPanel createInstancesPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(new TitledBorder("Discovered Supabase Instances"));
        
        instanceTableModel = new InstanceTableModel();
        instanceTable = new JTable(instanceTableModel);
        instanceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        instanceTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                onInstanceSelected();
            }
        });

        // Add right-click context menu for instances
        JPopupMenu instancePopupMenu = new JPopupMenu();
        JMenuItem copyOpenApiCurlItem = new JMenuItem("Copy curl for OpenAPI spec");
        copyOpenApiCurlItem.addActionListener(e -> copyInstanceOpenApiAsCurl());
        instancePopupMenu.add(copyOpenApiCurlItem);

        JMenuItem copyEnumTablesCurlItem = new JMenuItem("Copy curl for table enumeration");
        copyEnumTablesCurlItem.addActionListener(e -> copyInstanceEnumTablesCurl());
        instancePopupMenu.add(copyEnumTablesCurlItem);

        instanceTable.setComponentPopupMenu(instancePopupMenu);

        JScrollPane scrollPane = new JScrollPane(instanceTable);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        // Buttons panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        scanButton = new JButton("Test RLS");
        scanButton.addActionListener(this::onScanClicked);
        buttonPanel.add(scanButton);
        
        clearButton = new JButton("Clear All");
        clearButton.addActionListener(e -> onClearClicked());
        buttonPanel.add(clearButton);
        
        JButton exportButton = new JButton("Export");
        exportButton.addActionListener(e -> onExportClicked());
        buttonPanel.add(exportButton);

        progressBar = new JProgressBar();
        progressBar.setVisible(false);
        progressBar.setPreferredSize(new Dimension(150, 20));
        buttonPanel.add(progressBar);
        
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    private JPanel createBottomPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        
        // Split between tables and status
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split.setResizeWeight(0.6);
        
        // Vulnerable tables panel
        JPanel tablesPanel = new JPanel(new BorderLayout());
        tablesPanel.setBorder(new TitledBorder("Vulnerable Tables"));

        vulnerableTableModel = new VulnerableTableModel();
        vulnerableTable = new JTable(vulnerableTableModel);
        vulnerableTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Apply severity color renderer to the Severity column (index 1)
        vulnerableTable.getColumnModel().getColumn(1).setCellRenderer(
            new VulnerableTableModel.SeverityCellRenderer());

        // Add right-click context menu for copying as curl
        JPopupMenu tablePopupMenu = new JPopupMenu();
        JMenuItem copyAsCurlItem = new JMenuItem("Copy as curl");
        copyAsCurlItem.addActionListener(e -> copySelectedTableAsCurl());
        tablePopupMenu.add(copyAsCurlItem);

        JMenuItem copyAsCurlWriteItem = new JMenuItem("Copy as curl (POST/Write test)");
        copyAsCurlWriteItem.addActionListener(e -> copySelectedTableAsCurlWrite());
        tablePopupMenu.add(copyAsCurlWriteItem);

        vulnerableTable.setComponentPopupMenu(tablePopupMenu);

        JScrollPane tableScroll = new JScrollPane(vulnerableTable);
        tablesPanel.add(tableScroll, BorderLayout.CENTER);
        
        split.setLeftComponent(tablesPanel);
        
        // Status panel
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusPanel.setBorder(new TitledBorder("Status"));
        
        statusArea = new JTextArea();
        statusArea.setEditable(false);
        statusArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        JScrollPane statusScroll = new JScrollPane(statusArea);
        statusPanel.add(statusScroll, BorderLayout.CENTER);
        
        split.setRightComponent(statusPanel);
        
        panel.add(split, BorderLayout.CENTER);
        
        return panel;
    }
    
    private JPanel createConfigPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(new TitledBorder("Configuration"));
        panel.setPreferredSize(new Dimension(200, 0));

        // Scanning options - align all to left
        passiveScanCheckbox = new JCheckBox("Passive Scanning");
        passiveScanCheckbox.setSelected(config.isPassiveScanningEnabled());
        passiveScanCheckbox.setAlignmentX(LEFT_ALIGNMENT);
        passiveScanCheckbox.addActionListener(e ->
            config.setPassiveScanningEnabled(passiveScanCheckbox.isSelected()));
        panel.add(passiveScanCheckbox);

        activeScanCheckbox = new JCheckBox("Active Testing");
        activeScanCheckbox.setSelected(config.isActiveTestingEnabled());
        activeScanCheckbox.setAlignmentX(LEFT_ALIGNMENT);
        activeScanCheckbox.addActionListener(e ->
            config.setActiveTestingEnabled(activeScanCheckbox.isSelected()));
        panel.add(activeScanCheckbox);

        autoEnumerateCheckbox = new JCheckBox("Auto-Enumerate");
        autoEnumerateCheckbox.setSelected(config.isAutoEnumerateEnabled());
        autoEnumerateCheckbox.setAlignmentX(LEFT_ALIGNMENT);
        autoEnumerateCheckbox.setToolTipText("Automatically enumerate tables when a new Supabase instance with valid credentials is discovered");
        autoEnumerateCheckbox.addActionListener(e -> {
            config.setAutoEnumerateEnabled(autoEnumerateCheckbox.isSelected());
            logging.logToOutput("[*] Auto-enumerate: " +
                (autoEnumerateCheckbox.isSelected() ? "ENABLED" : "DISABLED"));
        });
        panel.add(autoEnumerateCheckbox);

        panel.add(Box.createVerticalStrut(20));

        // Info text area (plain text instead of HTML)
        JTextArea infoArea = new JTextArea(
            "Passive scanning detects\n" +
            "Supabase instances.\n\n" +
            "Active Testing enables RLS\n" +
            "bypass checks on tables.\n\n" +
            "Auto-Enumerate automatically\n" +
            "scans new instances.\n\n" +
            "Use 'Test RLS' button to\n" +
            "manually test for RLS bypass."
        );
        infoArea.setEditable(false);
        infoArea.setOpaque(false);
        infoArea.setAlignmentX(LEFT_ALIGNMENT);
        infoArea.setFont(infoArea.getFont().deriveFont(11f));
        infoArea.setLineWrap(true);
        infoArea.setWrapStyleWord(true);
        panel.add(infoArea);

        panel.add(Box.createVerticalStrut(15));

        // Disclaimer notice panel - clean style with border only
        JPanel disclaimerPanel = new JPanel();
        disclaimerPanel.setLayout(new BoxLayout(disclaimerPanel, BoxLayout.Y_AXIS));
        disclaimerPanel.setOpaque(false); // No background color
        disclaimerPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(2, 0, 0, 0, new Color(200, 200, 200)), // Top border line
            BorderFactory.createEmptyBorder(10, 0, 5, 0)
        ));
        disclaimerPanel.setAlignmentX(LEFT_ALIGNMENT);

        // Header with warning icon
        JLabel headerLabel = new JLabel("\u26A0 NOTICE");
        headerLabel.setFont(headerLabel.getFont().deriveFont(Font.BOLD, 13f));
        headerLabel.setForeground(new Color(180, 80, 0)); // Dark orange
        headerLabel.setAlignmentX(LEFT_ALIGNMENT);
        disclaimerPanel.add(headerLabel);
        disclaimerPanel.add(Box.createVerticalStrut(8));

        JTextArea disclaimerText = new JTextArea(
            "This tool provides basic security checks only\u2014not suitable for " +
            "production applications.\n\n" +
            "For comprehensive security audits, compliance reviews, " +
            "threat modeling, and production readiness validation, " +
            "reach out to Securify AI for one complimentary consultation:"
        );
        disclaimerText.setEditable(false);
        disclaimerText.setOpaque(false);
        disclaimerText.setFont(disclaimerText.getFont().deriveFont(12f));
        disclaimerText.setLineWrap(true);
        disclaimerText.setWrapStyleWord(true);
        disclaimerText.setAlignmentX(LEFT_ALIGNMENT);
        disclaimerPanel.add(disclaimerText);

        disclaimerPanel.add(Box.createVerticalStrut(8));

        // Email as clickable box
        JPanel emailBox = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        emailBox.setBackground(new Color(240, 248, 255)); // Light blue background
        emailBox.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(0, 102, 204), 1),
            BorderFactory.createEmptyBorder(6, 10, 6, 10)
        ));
        emailBox.setCursor(new Cursor(Cursor.HAND_CURSOR));
        emailBox.setAlignmentX(LEFT_ALIGNMENT);
        emailBox.setMaximumSize(new Dimension(Integer.MAX_VALUE, 35));

        JLabel emailIcon = new JLabel("\u2709 "); // Envelope icon
        emailIcon.setFont(emailIcon.getFont().deriveFont(12f));
        emailIcon.setForeground(new Color(0, 102, 204));
        emailBox.add(emailIcon);

        JLabel emailLabel = new JLabel("contact@securifyai.co");
        emailLabel.setFont(emailLabel.getFont().deriveFont(Font.BOLD, 12f));
        emailLabel.setForeground(new Color(0, 102, 204));
        emailBox.add(emailLabel);

        // Run mail invocation off the EDT to keep Burp UI responsive
        emailBox.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent e) {
                executor.submit(() -> {
                    try {
                        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.MAIL)) {
                            Desktop.getDesktop().mail(new java.net.URI("mailto:contact@securifyai.co"));
                        } else {
                            copyToClipboard("contact@securifyai.co");
                            SwingUtilities.invokeLater(() ->
                                logStatus("Email copied to clipboard: contact@securifyai.co")
                            );
                        }
                    } catch (Exception ex) {
                        copyToClipboard("contact@securifyai.co");
                        SwingUtilities.invokeLater(() ->
                            logStatus("Email copied to clipboard: contact@securifyai.co")
                        );
                    }
                });
            }
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                emailBox.setBackground(new Color(220, 238, 255)); // Slightly darker on hover
                emailBox.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(new Color(0, 70, 150), 1),
                    BorderFactory.createEmptyBorder(6, 10, 6, 10)
                ));
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                emailBox.setBackground(new Color(240, 248, 255)); // Back to normal
                emailBox.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createLineBorder(new Color(0, 102, 204), 1),
                    BorderFactory.createEmptyBorder(6, 10, 6, 10)
                ));
            }
        });
        disclaimerPanel.add(emailBox);

        // Wrap disclaimer in a container that won't expand
        JPanel disclaimerWrapper = new JPanel(new BorderLayout());
        disclaimerWrapper.setOpaque(false);
        disclaimerWrapper.setAlignmentX(LEFT_ALIGNMENT);
        disclaimerWrapper.add(disclaimerPanel, BorderLayout.NORTH);

        panel.add(disclaimerWrapper);

        return panel;
    }

    private void setupListeners() {
        // Listen for new instance discoveries
        instanceStore.addNewInstanceListener(instance -> {
            SwingUtilities.invokeLater(() -> {
                instanceTableModel.addInstance(instance);
                logStatus("Discovered: " + instance.getBaseUrl());
            });
        });

        // Listen for instance updates
        instanceStore.addInstanceUpdateListener(instance -> {
            SwingUtilities.invokeLater(() -> {
                instanceTableModel.updateInstance(instance);
            });
        });
    }

    private void onInstanceSelected() {
        int row = instanceTable.getSelectedRow();
        if (row >= 0) {
            SupabaseInstance instance = instanceTableModel.getInstanceAt(row);
            if (instance != null) {
                vulnerableTableModel.setTables(instance.getTables());
            }
        }
    }

    /**
     * Get the Burp Suite main frame for use as dialog parent.
     * This ensures dialogs are properly parented to Burp's window.
     */
    private Frame getBurpFrame() {
        return api.userInterface().swingUtils().suiteFrame();
    }

    private void onScanClicked(ActionEvent e) {
        int row = instanceTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(getBurpFrame(),
                "Please select a Supabase instance to test.",
                "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        SupabaseInstance instance = instanceTableModel.getInstanceAt(row);
        if (instance == null || !instance.hasValidCredentials()) {
            JOptionPane.showMessageDialog(getBurpFrame(),
                "Selected instance does not have valid credentials.",
                "Invalid Instance", JOptionPane.WARNING_MESSAGE);
            return;
        }

        // Confirm active testing
        int confirm = JOptionPane.showConfirmDialog(getBurpFrame(),
            "This will actively test the Supabase instance for RLS vulnerabilities.\n" +
            "Only proceed if you have authorization to test this target.\n\n" +
            "Continue?",
            "Confirm Active Testing",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);

        if (confirm != JOptionPane.YES_OPTION) {
            return;
        }

        // Run scan in background
        scanButton.setEnabled(false);
        progressBar.setIndeterminate(true);
        progressBar.setVisible(true);
        logStatus("Starting RLS scan on " + instance.getBaseUrl() + "...");

        executor.submit(() -> {
            try {
                ScanResult result = activeScanner.scanInstance(instance);

                // Wire findings into Burp's Scanner issue panel via SiteMap
                if (scanCheck != null) {
                    List<AuditIssue> issues = scanCheck.createRlsBypassIssues(instance, null);
                    for (AuditIssue issue : issues) {
                        api.siteMap().add(issue);
                    }
                }

                SwingUtilities.invokeLater(() -> {
                    instanceTableModel.updateInstance(instance);
                    vulnerableTableModel.setTables(instance.getTables());
                    logStatus(result.getSummary());

                    if (result.getVulnerableTables().size() > 0) {
                        logStatus("WARNING: Found " + result.getVulnerableTables().size() +
                            " tables with sensitive data!");
                    }
                });
            } catch (Exception ex) {
                // Log error message and full stack trace for debugging
                // Burp does not catch and report exceptions in background threads
                logging.logToError("Background scan error: " + ex.getMessage());
                logging.logToError("Stack trace: " + getStackTraceAsString(ex));
                SwingUtilities.invokeLater(() ->
                    logStatus("Error: " + ex.getMessage()));
            } finally {
                SwingUtilities.invokeLater(() -> {
                    scanButton.setEnabled(true);
                    progressBar.setVisible(false);
                });
            }
        });
    }

    /**
     * Convert an exception's stack trace to a string for logging.
     * This is useful for debugging background thread exceptions since
     * Burp does not automatically report them.
     */
    private String getStackTraceAsString(Exception e) {
        java.io.StringWriter sw = new java.io.StringWriter();
        java.io.PrintWriter pw = new java.io.PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }

    private void onClearClicked() {
        instanceStore.clear();
        if (scanCheck != null) {
            scanCheck.clear();
        }
        if (passiveScanner != null) {
            passiveScanner.clear();
        }
        instanceTableModel.clear();
        vulnerableTableModel.clear();
        statusArea.setText("");
        logStatus("Cleared all instances.");
    }

    private void onExportClicked() {
        List<SupabaseInstance> instances = instanceTableModel.getAllInstances();
        if (instances.isEmpty()) {
            JOptionPane.showMessageDialog(getBurpFrame(),
                "No instances to export.",
                "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Findings");
        fileChooser.setFileFilter(new FileNameExtensionFilter("JSON Files", "json"));
        fileChooser.setSelectedFile(new File("supabase-scan-results.json"));

        if (fileChooser.showSaveDialog(getBurpFrame()) == JFileChooser.APPROVE_OPTION) {
            try {
                File file = fileChooser.getSelectedFile();
                if (!file.getName().endsWith(".json")) {
                    file = new File(file.getAbsolutePath() + ".json");
                }
                ReportExporter.exportToFile(instances, file.getAbsolutePath());
                logStatus("Exported to: " + file.getAbsolutePath());
                JOptionPane.showMessageDialog(getBurpFrame(),
                    "Findings exported successfully!",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                logging.logToError("Export error: " + ex.getMessage());
                JOptionPane.showMessageDialog(getBurpFrame(),
                    "Export failed: " + ex.getMessage(),
                    "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    /**
     * Log a status message to the status area.
     * Thread-safe - can be called from any thread.
     */
    public void logStatus(String message) {
        Runnable update = () -> {
            statusArea.append(java.time.LocalTime.now().toString().substring(0, 8) +
                " - " + message + "\n");
            statusArea.setCaretPosition(statusArea.getDocument().getLength());
        };
        if (javax.swing.SwingUtilities.isEventDispatchThread()) {
            update.run();
        } else {
            javax.swing.SwingUtilities.invokeLater(update);
        }
    }

    /**
     * Get the instance table model for external updates.
     */
    public InstanceTableModel getInstanceTableModel() {
        return instanceTableModel;
    }

    /**
     * Shutdown the executor service promptly on extension unload.
     */
    public void shutdown() {
        executor.shutdownNow();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                logging.logToOutput("Executor did not terminate within 5 seconds.");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Copy the selected vulnerable table as a curl command (GET/Read).
     */
    private void copySelectedTableAsCurl() {
        int selectedRow = vulnerableTable.getSelectedRow();
        if (selectedRow < 0) {
            logStatus("No table selected");
            return;
        }

        // Get selected instance
        int instanceRow = instanceTable.getSelectedRow();
        if (instanceRow < 0) {
            logStatus("No instance selected");
            return;
        }

        SupabaseInstance instance = instanceTableModel.getInstanceAt(instanceRow);
        String tableName = (String) vulnerableTableModel.getValueAt(selectedRow, 0);

        if (instance == null || instance.getJwtToken() == null) {
            logStatus("Instance or JWT not available");
            return;
        }

        String curl = String.format(
            "curl -s \"%s/rest/v1/%s?limit=100\" \\\n  -H \"apikey: %s\" \\\n  -H \"Authorization: Bearer %s\"",
            instance.getBaseUrl(),
            tableName,
            instance.getJwtToken(),
            instance.getJwtToken()
        );

        copyToClipboard(curl);
        logStatus("Copied curl command for table: " + tableName);
    }

    /**
     * Copy the selected vulnerable table as a curl command (POST/Write test).
     */
    private void copySelectedTableAsCurlWrite() {
        int selectedRow = vulnerableTable.getSelectedRow();
        if (selectedRow < 0) {
            logStatus("No table selected");
            return;
        }

        // Get selected instance
        int instanceRow = instanceTable.getSelectedRow();
        if (instanceRow < 0) {
            logStatus("No instance selected");
            return;
        }

        SupabaseInstance instance = instanceTableModel.getInstanceAt(instanceRow);
        String tableName = (String) vulnerableTableModel.getValueAt(selectedRow, 0);

        if (instance == null || instance.getJwtToken() == null) {
            logStatus("Instance or JWT not available");
            return;
        }

        String curl = String.format(
            "curl -s \"%s/rest/v1/%s\" \\\n  -H \"apikey: %s\" \\\n  -H \"Authorization: Bearer %s\" \\\n  -H \"Content-Type: application/json\" \\\n  -H \"Prefer: return=minimal\" \\\n  -d '{}'",
            instance.getBaseUrl(),
            tableName,
            instance.getJwtToken(),
            instance.getJwtToken()
        );

        copyToClipboard(curl);
        logStatus("Copied curl (POST) command for table: " + tableName);
    }

    /**
     * Copy curl command for OpenAPI spec endpoint for selected instance.
     */
    private void copyInstanceOpenApiAsCurl() {
        int instanceRow = instanceTable.getSelectedRow();
        if (instanceRow < 0) {
            logStatus("No instance selected");
            return;
        }

        SupabaseInstance instance = instanceTableModel.getInstanceAt(instanceRow);
        if (instance == null || instance.getJwtToken() == null) {
            logStatus("Instance or JWT not available");
            return;
        }

        String curl = String.format(
            "curl -s \"%s/rest/v1/\" \\\n  -H \"apikey: %s\" \\\n  -H \"Authorization: Bearer %s\"",
            instance.getBaseUrl(),
            instance.getJwtToken(),
            instance.getJwtToken()
        );

        copyToClipboard(curl);
        logStatus("Copied curl for OpenAPI spec: " + instance.getBaseUrl());
    }

    /**
     * Copy curl command for table enumeration (same as OpenAPI but with jq parsing hint).
     */
    private void copyInstanceEnumTablesCurl() {
        int instanceRow = instanceTable.getSelectedRow();
        if (instanceRow < 0) {
            logStatus("No instance selected");
            return;
        }

        SupabaseInstance instance = instanceTableModel.getInstanceAt(instanceRow);
        if (instance == null || instance.getJwtToken() == null) {
            logStatus("Instance or JWT not available");
            return;
        }

        String curl = String.format(
            "curl -s \"%s/rest/v1/\" \\\n  -H \"apikey: %s\" \\\n  -H \"Authorization: Bearer %s\" \\\n  | jq -r '.paths | keys[] | select(startswith(\"/rpc/\") | not) | select(. != \"/\") | ltrimstr(\"/\")'",
            instance.getBaseUrl(),
            instance.getJwtToken(),
            instance.getJwtToken()
        );

        copyToClipboard(curl);
        logStatus("Copied curl for table enumeration: " + instance.getBaseUrl());
    }

    /**
     * Copy text to system clipboard.
     */
    private void copyToClipboard(String text) {
        java.awt.datatransfer.StringSelection selection =
            new java.awt.datatransfer.StringSelection(text);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
            .setContents(selection, selection);
    }
}
