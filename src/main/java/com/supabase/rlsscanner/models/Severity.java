/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Severity levels for detected vulnerabilities
 */

package com.supabase.rlsscanner.models;

/**
 * Severity classification for RLS vulnerabilities.
 * Based on the type of sensitive data exposed.
 */
public enum Severity {
    /**
     * Critical: passwords, secrets, api_keys, tokens, credit cards, SSNs
     */
    CRITICAL("Critical", "#FF0000", 4),
    
    /**
     * High: emails, phone numbers, personal IDs, financial data
     */
    HIGH("High", "#FF6600", 3),
    
    /**
     * Medium: addresses, device IDs, other PII
     */
    MEDIUM("Medium", "#FFCC00", 2),
    
    /**
     * Low: potentially sensitive but low-risk data
     */
    LOW("Low", "#00CCFF", 1),
    
    /**
     * Info: public/non-sensitive data
     */
    INFO("Info", "#00FF00", 0),
    
    /**
     * None: no sensitive data detected
     */
    NONE("None", "#CCCCCC", -1);
    
    private final String displayName;
    private final String colorHex;
    private final int priority;
    
    Severity(String displayName, String colorHex, int priority) {
        this.displayName = displayName;
        this.colorHex = colorHex;
        this.priority = priority;
    }
    
    public String getDisplayName() {
        return displayName;
    }
    
    public String getColorHex() {
        return colorHex;
    }
    
    public int getPriority() {
        return priority;
    }
    
    /**
     * Compare severity levels.
     * @param other The other severity to compare
     * @return true if this severity is higher than other
     */
    public boolean isHigherThan(Severity other) {
        return this.priority > other.priority;
    }
}

