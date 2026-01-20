/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Field analysis results
 */

package com.supabase.rlsscanner.models;

import java.util.ArrayList;
import java.util.List;

/**
 * Analysis results for a single table field.
 */
public class FieldAnalysis {
    private final String fieldName;
    private final List<String> detectionReasons;
    private final int sampleCount;
    private final Severity severity;
    
    public FieldAnalysis(String fieldName, List<String> detectionReasons, int sampleCount, Severity severity) {
        this.fieldName = fieldName;
        this.detectionReasons = new ArrayList<>(detectionReasons);
        this.sampleCount = sampleCount;
        this.severity = severity;
    }
    
    public String getFieldName() {
        return fieldName;
    }
    
    public List<String> getDetectionReasons() {
        return new ArrayList<>(detectionReasons);
    }
    
    public int getSampleCount() {
        return sampleCount;
    }
    
    public Severity getSeverity() {
        return severity;
    }
    
    @Override
    public String toString() {
        return String.format("FieldAnalysis{field='%s', reasons=%s, severity=%s}", 
            fieldName, detectionReasons, severity);
    }
}

