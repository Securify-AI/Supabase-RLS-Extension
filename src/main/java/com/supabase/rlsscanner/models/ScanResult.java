/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Scan result data model
 */

package com.supabase.rlsscanner.models;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents the result of an RLS security scan.
 */
public class ScanResult {
    private final SupabaseInstance instance;
    private final LocalDateTime scanTime;
    private final List<VulnerableTable> vulnerableTables;
    private final int totalTablesScanned;
    private final int accessibleTablesCount;
    private Severity highestSeverity;
    private String errorMessage;
    private boolean success;
    
    public ScanResult(SupabaseInstance instance) {
        this.instance = instance;
        this.scanTime = LocalDateTime.now();
        this.vulnerableTables = new ArrayList<>();
        this.totalTablesScanned = 0;
        this.accessibleTablesCount = 0;
        this.highestSeverity = Severity.NONE;
        this.success = false;
    }
    
    public ScanResult(SupabaseInstance instance, int totalTablesScanned, int accessibleTablesCount) {
        this.instance = instance;
        this.scanTime = LocalDateTime.now();
        this.vulnerableTables = new ArrayList<>();
        this.totalTablesScanned = totalTablesScanned;
        this.accessibleTablesCount = accessibleTablesCount;
        this.highestSeverity = Severity.NONE;
        this.success = true;
    }
    
    // Getters
    public SupabaseInstance getInstance() { return instance; }
    public LocalDateTime getScanTime() { return scanTime; }
    public List<VulnerableTable> getVulnerableTables() { return new ArrayList<>(vulnerableTables); }
    public int getTotalTablesScanned() { return totalTablesScanned; }
    public int getAccessibleTablesCount() { return accessibleTablesCount; }
    public Severity getHighestSeverity() { return highestSeverity; }
    public String getErrorMessage() { return errorMessage; }
    public boolean isSuccess() { return success; }
    
    // Setters
    public void setErrorMessage(String errorMessage) { 
        this.errorMessage = errorMessage;
        this.success = false;
    }
    public void setSuccess(boolean success) { this.success = success; }
    
    /**
     * Add a vulnerable table to the results.
     */
    public void addVulnerableTable(VulnerableTable table) {
        if (table.hasSensitiveData()) {
            vulnerableTables.add(table);
            if (table.getSeverity().isHigherThan(highestSeverity)) {
                highestSeverity = table.getSeverity();
            }
        }
    }
    
    /**
     * Get counts by severity level.
     */
    public int getCountBySeverity(Severity severity) {
        return (int) vulnerableTables.stream()
            .filter(t -> t.getSeverity() == severity)
            .count();
    }
    
    /**
     * Generate a summary of the scan results.
     */
    public String getSummary() {
        if (!success) {
            return String.format("Scan failed: %s", errorMessage);
        }
        
        int critical = getCountBySeverity(Severity.CRITICAL);
        int high = getCountBySeverity(Severity.HIGH);
        int medium = getCountBySeverity(Severity.MEDIUM);
        
        return String.format("Scanned %d tables, %d accessible. Vulnerabilities: %d Critical, %d High, %d Medium",
            totalTablesScanned, accessibleTablesCount, critical, high, medium);
    }
    
    @Override
    public String toString() {
        return getSummary();
    }
}

