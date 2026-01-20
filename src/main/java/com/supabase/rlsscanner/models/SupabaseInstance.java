/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Supabase instance data model
 */

package com.supabase.rlsscanner.models;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Represents a discovered Supabase instance with its credentials and findings.
 * Supports both anon and service_role tokens for the same URL.
 */
public class SupabaseInstance {
    private final String baseUrl;

    // Support for multiple JWT tokens (anon and service_role)
    private String anonToken;
    private String serviceRoleToken;

    private String sourceUrl;
    private String discoveryContext;
    private LocalDateTime discoveredAt;
    private List<VulnerableTable> tables;
    private boolean tested;
    private Severity overallSeverity;

    public SupabaseInstance(String baseUrl) {
        this.baseUrl = normalizeUrl(baseUrl);
        this.discoveredAt = LocalDateTime.now();
        this.tables = new ArrayList<>();
        this.tested = false;
        this.overallSeverity = Severity.NONE;
    }
    
    /**
     * Normalize the Supabase URL by removing trailing slashes.
     */
    private static String normalizeUrl(String url) {
        if (url == null) return null;
        return url.replaceAll("/+$", "");
    }
    
    // Getters
    public String getBaseUrl() { return baseUrl; }
    public String getAnonToken() { return anonToken; }
    public String getServiceRoleToken() { return serviceRoleToken; }

    /**
     * Get the primary JWT token for display (prefers anon, falls back to service_role).
     */
    public String getJwtToken() {
        return anonToken != null ? anonToken : serviceRoleToken;
    }

    /**
     * Get the JWT role for display (based on available tokens).
     */
    public String getJwtRole() {
        if (anonToken != null && serviceRoleToken != null) {
            return "anon + service_role";
        } else if (serviceRoleToken != null) {
            return "service_role";
        } else if (anonToken != null) {
            return "anon";
        }
        return null;
    }

    public boolean hasServiceRoleToken() { return serviceRoleToken != null; }
    public boolean hasAnonToken() { return anonToken != null; }
    public String getSourceUrl() { return sourceUrl; }
    public String getDiscoveryContext() { return discoveryContext; }
    public LocalDateTime getDiscoveredAt() { return discoveredAt; }
    public List<VulnerableTable> getTables() { return new ArrayList<>(tables); }
    public boolean isTested() { return tested; }
    public Severity getOverallSeverity() { return overallSeverity; }

    // Setters
    public void setAnonToken(String anonToken) {
        this.anonToken = anonToken;
    }

    public void setServiceRoleToken(String serviceRoleToken) {
        this.serviceRoleToken = serviceRoleToken;
        // Service role token is always CRITICAL if exposed
        if (serviceRoleToken != null && this.overallSeverity.getPriority() < Severity.CRITICAL.getPriority()) {
            this.overallSeverity = Severity.CRITICAL;
        }
    }

    /**
     * Legacy setter for backward compatibility - routes to appropriate token based on role.
     */
    @Deprecated
    public void setJwtToken(String jwtToken) {
        // This is kept for backward compatibility but shouldn't be used
        if (anonToken == null) {
            this.anonToken = jwtToken;
        }
    }

    public void setSourceUrl(String sourceUrl) { this.sourceUrl = sourceUrl; }
    public void setDiscoveryContext(String discoveryContext) { this.discoveryContext = discoveryContext; }
    public void setTested(boolean tested) { this.tested = tested; }
    public void setOverallSeverity(Severity severity) { this.overallSeverity = severity; }
    
    /**
     * Add a table to this instance.
     */
    public void addTable(VulnerableTable table) {
        this.tables.add(table);
        updateOverallSeverity();
    }
    
    /**
     * Set all tables and recalculate severity.
     */
    public void setTables(List<VulnerableTable> tables) {
        this.tables = new ArrayList<>(tables);
        updateOverallSeverity();
    }
    
    /**
     * Update the overall severity based on the most severe table finding.
     */
    private void updateOverallSeverity() {
        this.overallSeverity = tables.stream()
            .map(VulnerableTable::getSeverity)
            .filter(Objects::nonNull)
            .max((s1, s2) -> Integer.compare(s1.getPriority(), s2.getPriority()))
            .orElse(Severity.NONE);
    }
    
    /**
     * Get count of vulnerable tables.
     */
    public int getVulnerableTableCount() {
        return (int) tables.stream().filter(VulnerableTable::hasSensitiveData).count();
    }
    
    /**
     * Get a sanitized JWT token for display (shows only first/last few chars).
     */
    public String getSanitizedJwt() {
        String token = getJwtToken();
        if (token == null || token.length() < 20) {
            return "[no token]";
        }
        return token.substring(0, 10) + "..." + token.substring(token.length() - 10);
    }

    /**
     * Get formatted token display showing both tokens if available.
     */
    public String getTokenDisplay() {
        if (anonToken != null && serviceRoleToken != null) {
            return "anon + service_role";
        } else if (serviceRoleToken != null) {
            return sanitizeToken(serviceRoleToken);
        } else if (anonToken != null) {
            return sanitizeToken(anonToken);
        }
        return "[no token]";
    }

    private String sanitizeToken(String token) {
        if (token == null || token.length() < 20) {
            return "[invalid]";
        }
        return token.substring(0, 10) + "..." + token.substring(token.length() - 10);
    }

    /**
     * Check if this instance has valid credentials for testing.
     */
    public boolean hasValidCredentials() {
        return baseUrl != null && !baseUrl.isEmpty()
            && (hasAnonToken() || hasServiceRoleToken());
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SupabaseInstance that = (SupabaseInstance) o;
        return Objects.equals(baseUrl, that.baseUrl);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(baseUrl);
    }
    
    @Override
    public String toString() {
        return String.format("SupabaseInstance{url='%s', tested=%s, severity=%s, tables=%d}", 
            baseUrl, tested, overallSeverity, tables.size());
    }
}

