/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Burp Scanner integration
 */

package com.supabase.rlsscanner.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.supabase.rlsscanner.core.InstanceStore;
import com.supabase.rlsscanner.core.ScannerConfig;
import com.supabase.rlsscanner.models.Severity;
import com.supabase.rlsscanner.models.SupabaseInstance;
import com.supabase.rlsscanner.models.VulnerableTable;
import com.supabase.rlsscanner.utils.PatternMatcher;

import java.util.*;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static java.util.Collections.emptyList;

/**
 * Burp Scanner integration for detecting Supabase vulnerabilities.
 */
public class SupabaseScanCheck implements ScanCheck {
    
    private static final String ISSUE_NAME_JWT_EXPOSED = "Supabase JWT Token Exposed";
    private static final String ISSUE_NAME_RLS_BYPASS = "Supabase Row Level Security Bypass";
    
    private final MontoyaApi api;
    private final Logging logging;
    private final ScannerConfig config;
    private final InstanceStore instanceStore;
    private final ActiveScanner activeScanner;
    
    public SupabaseScanCheck(MontoyaApi api, ScannerConfig config, 
                             InstanceStore instanceStore, ActiveScanner activeScanner) {
        this.api = api;
        this.logging = api.logging();
        this.config = config;
        this.instanceStore = instanceStore;
        this.activeScanner = activeScanner;
    }
    
    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        if (!config.isPassiveScanningEnabled()) {
            return auditResult(emptyList());
        }
        
        List<AuditIssue> issues = new ArrayList<>();
        
        try {
            String body = baseRequestResponse.response().bodyToString();
            if (body == null || body.isEmpty()) {
                return auditResult(emptyList());
            }
            
            String url = baseRequestResponse.request().url();
            
            // Check for exposed JWT tokens
            List<String> jwts = PatternMatcher.extractJwtTokens(body);
            Set<String> supabaseUrls = PatternMatcher.extractSupabaseUrls(body);
            
            for (String jwt : jwts) {
                if (PatternMatcher.isSupabaseJwt(jwt)) {
                    List<Marker> markers = findMarkers(body, jwt);
                    
                    issues.add(auditIssue(
                        ISSUE_NAME_JWT_EXPOSED,
                        buildJwtExposureDescription(jwt, supabaseUrls),
                        buildJwtRemediationDetail(),
                        url,
                        AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.CERTAIN,
                        buildJwtBackground(),
                        null,
                        AuditIssueSeverity.HIGH,
                        baseRequestResponse.withResponseMarkers(markers)
                    ));
                    
                    // Store for later testing
                    for (String supabaseUrl : supabaseUrls) {
                        instanceStore.addOrUpdate(supabaseUrl, jwt, url, "Scanner detection");
                    }
                }
            }
            
        } catch (Exception e) {
            logging.logToError("Passive audit error: " + e.getMessage());
        }
        
        return auditResult(issues);
    }
    
    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, 
                                    AuditInsertionPoint auditInsertionPoint) {
        if (!config.isActiveTestingEnabled()) {
            return auditResult(emptyList());
        }
        
        // Active testing is handled separately via the UI
        // This prevents automatic aggressive scanning
        return auditResult(emptyList());
    }
    
    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        // Keep both if they're for different URLs/tables
        if (existingIssue.name().equals(newIssue.name())) {
            if (existingIssue.baseUrl().equals(newIssue.baseUrl())) {
                return KEEP_EXISTING;
            }
        }
        return KEEP_BOTH;
    }
    
    /**
     * Create scanner issues for RLS bypass findings.
     */
    public List<AuditIssue> createRlsBypassIssues(SupabaseInstance instance, 
                                                   HttpRequestResponse requestResponse) {
        List<AuditIssue> issues = new ArrayList<>();
        
        for (VulnerableTable table : instance.getTables()) {
            if (!table.hasSensitiveData()) continue;
            
            issues.add(auditIssue(
                ISSUE_NAME_RLS_BYPASS,
                buildRlsDescription(instance, table),
                buildRlsRemediationDetail(),
                instance.getBaseUrl() + "/rest/v1/" + table.getTableName(),
                mapSeverity(table.getSeverity()),
                AuditIssueConfidence.FIRM,
                buildRlsBackground(),
                null,
                mapSeverity(table.getSeverity()),
                requestResponse
            ));
        }
        
        return issues;
    }
    
    /**
     * Find markers for highlighting in response.
     */
    private List<Marker> findMarkers(String body, String match) {
        List<Marker> markers = new ArrayList<>();
        int start = 0;
        while ((start = body.indexOf(match, start)) != -1) {
            markers.add(Marker.marker(start, start + match.length()));
            start += match.length();
        }
        return markers;
    }

    /**
     * Map internal severity to Burp severity.
     */
    private AuditIssueSeverity mapSeverity(Severity severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> AuditIssueSeverity.HIGH;
            case MEDIUM -> AuditIssueSeverity.MEDIUM;
            case LOW -> AuditIssueSeverity.LOW;
            default -> AuditIssueSeverity.INFORMATION;
        };
    }

    /**
     * Escape HTML special characters to prevent XSS in issue descriptions.
     * This is important since table names and field names come from HTTP responses.
     */
    private String escapeHtml(String input) {
        if (input == null) {
            return "";
        }
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;");
    }

    private String buildJwtExposureDescription(String jwt, Set<String> urls) {
        StringBuilder sb = new StringBuilder();
        sb.append("<p>A Supabase JWT token was found exposed in the response.</p>");
        sb.append("<p><b>Token (sanitized):</b> ");
        sb.append(escapeHtml(jwt.substring(0, Math.min(20, jwt.length())))).append("...");
        sb.append("</p>");
        if (!urls.isEmpty()) {
            sb.append("<p><b>Associated Supabase URLs:</b></p><ul>");
            for (String url : urls) {
                sb.append("<li>").append(escapeHtml(url)).append("</li>");
            }
            sb.append("</ul>");
        }
        return sb.toString();
    }

    private String buildJwtBackground() {
        return "<p>Supabase uses JWT tokens to authenticate API requests. When these tokens " +
               "are exposed in client-side code, attackers can use them to directly access " +
               "the Supabase database, potentially bypassing Row Level Security policies.</p>";
    }

    private String buildJwtRemediationDetail() {
        return "<p>Ensure that JWT tokens are not exposed in client-side code. Use server-side " +
               "authentication and proper Row Level Security (RLS) policies to protect data.</p>";
    }

    private String buildRlsDescription(SupabaseInstance instance, VulnerableTable table) {
        StringBuilder sb = new StringBuilder();
        sb.append("<p>Row Level Security bypass detected on table <b>")
          .append(escapeHtml(table.getTableName())).append("</b>.</p>");
        sb.append("<p><b>Severity:</b> ").append(escapeHtml(String.valueOf(table.getSeverity()))).append("</p>");
        sb.append("<p><b>Rows accessible:</b> ").append(table.getRowCount()).append("</p>");
        sb.append("<p><b>Sensitive fields detected:</b></p><ul>");
        for (String field : table.getSensitiveFields()) {
            sb.append("<li>").append(escapeHtml(field)).append("</li>");
        }
        sb.append("</ul>");
        sb.append("<p><b>Supabase URL:</b> ").append(escapeHtml(instance.getBaseUrl())).append("</p>");
        return sb.toString();
    }

    private String buildRlsBackground() {
        return "<p>Supabase Row Level Security (RLS) allows database administrators to define " +
               "policies that restrict which rows can be accessed by which users. When RLS is " +
               "disabled or misconfigured, any user with a valid JWT token can access all data " +
               "in the table, including sensitive personal information.</p>";
    }

    private String buildRlsRemediationDetail() {
        return "<p>To fix this vulnerability:</p>" +
               "<ol>" +
               "<li>Enable Row Level Security on all tables containing sensitive data</li>" +
               "<li>Create appropriate RLS policies that restrict access based on user identity</li>" +
               "<li>Test policies thoroughly to ensure they work as expected</li>" +
               "<li>Consider using service role keys only on the server side</li>" +
               "</ol>";
    }
}
