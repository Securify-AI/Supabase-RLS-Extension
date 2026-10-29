/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Vulnerable table data model
 */

package com.supabase.rlsscanner.models;

import burp.api.montoya.http.message.HttpRequestResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents a Supabase table with potential RLS bypass vulnerabilities.
 */
public class VulnerableTable {

    // Detection status enum
    public enum DetectionStatus {
        YES("Yes"),
        NO("No"),
        UNKNOWN("?");

        private final String display;
        DetectionStatus(String display) { this.display = display; }
        public String getDisplay() { return display; }
    }

    private final String tableName;
    private int rowCount;
    private Severity severity;
    private List<String> sensitiveFields;
    private Map<String, FieldAnalysis> fieldAnalysis;
    private boolean accessible;
    private int httpStatus;
    private String errorMessage;

    // Access permissions
    private DetectionStatus readAccess = DetectionStatus.UNKNOWN;
    private DetectionStatus writeAccess = DetectionStatus.UNKNOWN;

    // Sensitive data detection
    private DetectionStatus hasPii = DetectionStatus.UNKNOWN;

    // Column names
    private List<String> columns = new ArrayList<>();

    // RLS status
    private String rlsStatus = "Unknown";
    private HttpRequestResponse requestResponse;

    public VulnerableTable(String tableName) {
        this.tableName = tableName;
        this.rowCount = 0;
        this.severity = Severity.NONE;
        this.sensitiveFields = new ArrayList<>();
        this.fieldAnalysis = new HashMap<>();
        this.accessible = false;
        this.httpStatus = 0;
        this.columns = new ArrayList<>();
    }

    // Getters
    public String getTableName() { return tableName; }
    public int getRowCount() { return rowCount; }
    public Severity getSeverity() { return severity; }
    public List<String> getSensitiveFields() { return new ArrayList<>(sensitiveFields); }
    public Map<String, FieldAnalysis> getFieldAnalysis() { return new HashMap<>(fieldAnalysis); }
    public boolean isAccessible() { return accessible; }
    public int getHttpStatus() { return httpStatus; }
    public String getErrorMessage() { return errorMessage; }
    public DetectionStatus getReadAccess() { return readAccess; }
    public DetectionStatus getWriteAccess() { return writeAccess; }
    public DetectionStatus getHasPii() { return hasPii; }
    public List<String> getColumns() { return new ArrayList<>(columns); }
    public String getColumnsDisplay() {
        if (columns.isEmpty()) return "-";
        return String.join(", ", columns);
    }
    public String getRlsStatus() { return rlsStatus; }
    public HttpRequestResponse getRequestResponse() { return requestResponse; }
    public void setRequestResponse(HttpRequestResponse requestResponse) { this.requestResponse = requestResponse; }

    // Setters
    public void setRowCount(int rowCount) { this.rowCount = rowCount; }
    public void setSeverity(Severity severity) { this.severity = severity; }
    public void setSensitiveFields(List<String> sensitiveFields) {
        this.sensitiveFields = new ArrayList<>(sensitiveFields);
    }
    public void setFieldAnalysis(Map<String, FieldAnalysis> fieldAnalysis) {
        this.fieldAnalysis = new HashMap<>(fieldAnalysis);
    }
    public void setAccessible(boolean accessible) { this.accessible = accessible; }
    public void setHttpStatus(int httpStatus) { this.httpStatus = httpStatus; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    public void setReadAccess(DetectionStatus readAccess) { this.readAccess = readAccess; }
    public void setWriteAccess(DetectionStatus writeAccess) { this.writeAccess = writeAccess; }
    public void setHasPii(DetectionStatus hasPii) { this.hasPii = hasPii; }
    public void setColumns(List<String> columns) { this.columns = new ArrayList<>(columns); }
    public void setRlsStatus(String rlsStatus) { this.rlsStatus = rlsStatus; }
    
    /**
     * Check if this table has any sensitive data exposed.
     */
    public boolean hasSensitiveData() {
        return !sensitiveFields.isEmpty() && severity != Severity.NONE && severity != Severity.INFO;
    }
    
    /**
     * Get a summary string for display.
     */
    public String getSummary() {
        if (!accessible) {
            return String.format("%s: blocked (HTTP %d)", tableName, httpStatus);
        }
        if (hasSensitiveData()) {
            return String.format("%s: %d rows - %s - Fields: %s", 
                tableName, rowCount, severity.getDisplayName(), 
                String.join(", ", sensitiveFields));
        }
        return String.format("%s: %d rows - Public data", tableName, rowCount);
    }
    
    @Override
    public String toString() {
        return getSummary();
    }
}

