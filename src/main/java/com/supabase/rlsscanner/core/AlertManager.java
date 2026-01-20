/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Alert manager for notifications
 */

package com.supabase.rlsscanner.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import com.supabase.rlsscanner.models.ScanResult;
import com.supabase.rlsscanner.models.Severity;
import com.supabase.rlsscanner.models.SupabaseInstance;
import com.supabase.rlsscanner.models.VulnerableTable;

import java.awt.*;
import java.util.List;

/**
 * Manages alerts and notifications for the scanner.
 */
public class AlertManager {
    
    private final MontoyaApi api;
    private final Logging logging;
    private final ScannerConfig config;
    
    public AlertManager(MontoyaApi api, ScannerConfig config) {
        this.api = api;
        this.logging = api.logging();
        this.config = config;
    }
    
    /**
     * Alert when a new Supabase instance is discovered.
     */
    public void alertInstanceDiscovered(SupabaseInstance instance) {
        String message = String.format(
            "⚠️ Supabase instance detected: %s",
            instance.getBaseUrl()
        );
        
        logging.logToOutput(message);
        
        if (instance.hasValidCredentials()) {
            logging.logToOutput("   JWT token found - ready for RLS testing");
        }
    }
    
    /**
     * Alert when RLS vulnerabilities are found.
     */
    public void alertVulnerabilitiesFound(ScanResult result) {
        if (!result.isSuccess() || result.getVulnerableTables().isEmpty()) {
            return;
        }
        
        SupabaseInstance instance = result.getInstance();
        List<VulnerableTable> vulnerables = result.getVulnerableTables();
        
        // Build alert message
        StringBuilder message = new StringBuilder();
        message.append("\n");
        message.append("🚨 ").append("=".repeat(50)).append("\n");
        message.append("🚨 SUPABASE RLS BYPASS DETECTED!\n");
        message.append("🚨 ").append("=".repeat(50)).append("\n");
        message.append("\n");
        message.append("Target: ").append(instance.getBaseUrl()).append("\n");
        message.append("Source: ").append(instance.getSourceUrl()).append("\n");
        message.append("\n");
        
        // Count by severity
        int critical = result.getCountBySeverity(Severity.CRITICAL);
        int high = result.getCountBySeverity(Severity.HIGH);
        int medium = result.getCountBySeverity(Severity.MEDIUM);
        
        message.append("VULNERABILITY SUMMARY:\n");
        if (critical > 0) {
            message.append("  🔴 Critical: ").append(critical).append(" table(s)\n");
        }
        if (high > 0) {
            message.append("  🟠 High: ").append(high).append(" table(s)\n");
        }
        if (medium > 0) {
            message.append("  🟡 Medium: ").append(medium).append(" table(s)\n");
        }
        message.append("\n");
        
        // List vulnerable tables
        message.append("AFFECTED TABLES:\n");
        for (VulnerableTable table : vulnerables) {
            String icon = switch (table.getSeverity()) {
                case CRITICAL -> "🔴";
                case HIGH -> "🟠";
                case MEDIUM -> "🟡";
                default -> "⚪";
            };
            message.append("  ").append(icon).append(" ").append(table.getTableName());
            message.append(" (").append(table.getRowCount()).append(" rows)");
            message.append(" - Sensitive fields: ");
            message.append(String.join(", ", table.getSensitiveFields()));
            message.append("\n");
        }
        
        message.append("\n");
        message.append("=".repeat(54)).append("\n");
        
        logging.logToOutput(message.toString());
        
        // Play sound if enabled
        if (config.isSoundAlertsEnabled()) {
            playAlertSound();
        }
    }
    
    /**
     * Play an alert sound.
     */
    private void playAlertSound() {
        try {
            Toolkit.getDefaultToolkit().beep();
        } catch (Exception e) {
            // Ignore sound errors
        }
    }
    
    /**
     * Log an error alert.
     */
    public void alertError(String context, String error) {
        logging.logToError(String.format("[%s] Error: %s", context, error));
    }
    
    /**
     * Log an info message.
     */
    public void info(String message) {
        logging.logToOutput("[*] " + message);
    }
    
    /**
     * Log a warning message.
     */
    public void warn(String message) {
        logging.logToOutput("[!] " + message);
    }
}

