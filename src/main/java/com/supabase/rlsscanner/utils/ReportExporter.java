/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Report export utilities
 */

package com.supabase.rlsscanner.utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.supabase.rlsscanner.models.SupabaseInstance;
import com.supabase.rlsscanner.models.VulnerableTable;

import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Utility class for exporting scan results to various formats.
 */
public class ReportExporter {
    
    private static final Gson GSON = new GsonBuilder()
        .setPrettyPrinting()
        .setDateFormat("yyyy-MM-dd'T'HH:mm:ss")
        .create();
    
    /**
     * Export findings to JSON format.
     */
    public static String exportToJson(List<SupabaseInstance> instances) {
        List<Map<String, Object>> findings = new ArrayList<>();
        
        for (SupabaseInstance instance : instances) {
            Map<String, Object> instanceData = new LinkedHashMap<>();
            instanceData.put("baseUrl", instance.getBaseUrl());
            instanceData.put("sourceUrl", instance.getSourceUrl());
            instanceData.put("jwtToken", instance.getSanitizedJwt());
            instanceData.put("tested", instance.isTested());
            instanceData.put("overallSeverity", instance.getOverallSeverity().getDisplayName());
            instanceData.put("discoveredAt", instance.getDiscoveredAt() != null 
                ? instance.getDiscoveredAt().toString() : null);
            
            // Tables
            List<Map<String, Object>> tables = new ArrayList<>();
            for (VulnerableTable table : instance.getTables()) {
                Map<String, Object> tableData = new LinkedHashMap<>();
                tableData.put("tableName", table.getTableName());
                tableData.put("accessible", table.isAccessible());
                tableData.put("rowCount", table.getRowCount());
                tableData.put("severity", table.getSeverity().getDisplayName());
                tableData.put("sensitiveFields", table.getSensitiveFields());
                tableData.put("hasSensitiveData", table.hasSensitiveData());
                
                if (table.getHttpStatus() > 0) {
                    tableData.put("httpStatus", table.getHttpStatus());
                }
                if (table.getErrorMessage() != null) {
                    tableData.put("error", table.getErrorMessage());
                }
                
                tables.add(tableData);
            }
            instanceData.put("tables", tables);
            
            // Summary
            Map<String, Object> summary = new LinkedHashMap<>();
            summary.put("totalTables", instance.getTables().size());
            summary.put("vulnerableTables", instance.getVulnerableTableCount());
            instanceData.put("summary", summary);
            
            findings.add(instanceData);
        }
        
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("reportType", "Supabase RLS Security Scan");
        report.put("generatedAt", LocalDateTime.now().toString());
        report.put("instanceCount", instances.size());
        report.put("findings", findings);
        
        return GSON.toJson(report);
    }
    
    /**
     * Export findings to a file.
     */
    public static void exportToFile(List<SupabaseInstance> instances, String filePath) 
            throws IOException {
        String json = exportToJson(instances);
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(json);
        }
    }
    
    /**
     * Generate a summary report as text.
     */
    public static String generateTextSummary(List<SupabaseInstance> instances) {
        StringBuilder sb = new StringBuilder();
        
        sb.append("SUPABASE RLS SECURITY SCAN REPORT\n");
        sb.append("=".repeat(50)).append("\n");
        sb.append("Generated: ").append(LocalDateTime.now()
            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("\n");
        sb.append("Instances scanned: ").append(instances.size()).append("\n\n");
        
        int totalVulnerable = 0;
        int totalCritical = 0;
        int totalHigh = 0;
        
        for (SupabaseInstance instance : instances) {
            sb.append("-".repeat(50)).append("\n");
            sb.append("Instance: ").append(instance.getBaseUrl()).append("\n");
            sb.append("Source: ").append(instance.getSourceUrl()).append("\n");
            sb.append("Status: ").append(instance.isTested() ? "Tested" : "Not tested").append("\n");
            
            if (instance.isTested()) {
                sb.append("Tables: ").append(instance.getTables().size()).append("\n");
                sb.append("Vulnerable: ").append(instance.getVulnerableTableCount()).append("\n");
                
                for (VulnerableTable table : instance.getTables()) {
                    if (table.hasSensitiveData()) {
                        totalVulnerable++;
                        if (table.getSeverity().name().equals("CRITICAL")) totalCritical++;
                        if (table.getSeverity().name().equals("HIGH")) totalHigh++;
                        
                        sb.append("  [").append(table.getSeverity().getDisplayName()).append("] ");
                        sb.append(table.getTableName()).append(" - ");
                        sb.append(table.getRowCount()).append(" rows\n");
                        sb.append("    Fields: ").append(String.join(", ", table.getSensitiveFields()));
                        sb.append("\n");
                    }
                }
            }
        }
        
        sb.append("\n").append("=".repeat(50)).append("\n");
        sb.append("SUMMARY\n");
        sb.append("Total vulnerable tables: ").append(totalVulnerable).append("\n");
        sb.append("Critical: ").append(totalCritical).append("\n");
        sb.append("High: ").append(totalHigh).append("\n");
        
        return sb.toString();
    }
    
    private ReportExporter() {
        // Utility class
    }
}

