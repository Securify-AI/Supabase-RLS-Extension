/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Burp Scanner integration
 */

package com.supabase.rlsscanner.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.supabase.rlsscanner.core.InstanceStore;
import com.supabase.rlsscanner.core.ScannerConfig;
import com.supabase.rlsscanner.models.Severity;
import com.supabase.rlsscanner.models.SupabaseInstance;
import com.supabase.rlsscanner.models.VulnerableTable;
import com.supabase.rlsscanner.utils.PatternMatcher;

import java.net.URI;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import static burp.api.montoya.scanner.AuditResult.auditResult;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_BOTH;
import static burp.api.montoya.scanner.ConsolidationAction.KEEP_EXISTING;
import static burp.api.montoya.scanner.audit.issues.AuditIssue.auditIssue;
import static java.util.Collections.emptyList;

/**
 * Burp Scanner integration for detecting Supabase vulnerabilities.
 * Implements modern Montoya PassiveScanCheck and ActiveScanCheck interfaces.
 */
public class SupabaseScanCheck implements PassiveScanCheck, ActiveScanCheck {
    
    private static final String CHECK_NAME = "Supabase RLS Security Scanner";
    private static final String ISSUE_NAME_JWT_EXPOSED = "Supabase JWT Token Exposed";
    private static final String ISSUE_NAME_SERVICE_ROLE_EXPOSED = "Supabase Service Role JWT Token Exposed";
    private static final String ISSUE_NAME_RLS_BYPASS = "Supabase Row Level Security Bypass";

    private static final Set<String> SCANNABLE_CONTENT_TYPES = Set.of(
        "text/html",
        "application/javascript",
        "text/javascript",
        "application/json",
        "text/plain"
    );
    
    private final MontoyaApi api;
    private final Logging logging;
    private final ScannerConfig config;
    private final InstanceStore instanceStore;
    private final ActiveScanner activeScanner;

    // Track which instances have been tested in active audit to avoid redundant scans
    private final Set<String> auditedInstances = ConcurrentHashMap.newKeySet();

    // Status listener for UI updates
    private Consumer<String> statusListener;
    
    public SupabaseScanCheck(MontoyaApi api, ScannerConfig config, 
                             InstanceStore instanceStore, ActiveScanner activeScanner) {
        this.api = api;
        this.logging = api.logging();
        this.config = config;
        this.instanceStore = instanceStore;
        this.activeScanner = activeScanner;
    }

    /**
     * Name of the check for Montoya scan check interfaces.
     */
    @Override
    public String checkName() {
        return CHECK_NAME;
    }

    /**
     * Scanner check name for UI labeling and issue tracking.
     */
    public String name() {
        return CHECK_NAME;
    }

    /**
     * Frequency declaration governing how Burp runs the check.
     */
    public ScanCheckType scanCheckType() {
        return ScanCheckType.PER_REQUEST;
    }

    /**
     * Set a listener to receive status updates.
     */
    public void setStatusListener(Consumer<String> listener) {
        this.statusListener = listener;
    }

    private void updateStatus(String message) {
        if (statusListener != null) {
            statusListener.accept(message);
        }
    }

    /**
     * Clear cached scan audit state.
     */
    public void clear() {
        auditedInstances.clear();
        logging.logToOutput("[*] Cleared scanner check state");
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        return passiveAudit(baseRequestResponse);
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse, 
                              AuditInsertionPoint auditInsertionPoint, 
                              Http http) {
        return activeAudit(baseRequestResponse, auditInsertionPoint);
    }
    
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        if (!config.isPassiveScanningEnabled()) {
            return auditResult(emptyList());
        }
        
        List<AuditIssue> issues = new ArrayList<>();
        
        try {
            HttpRequest request = baseRequestResponse.request();
            HttpResponse response = baseRequestResponse.response();

            String sourceUrl = request.url();
            Set<String> jwtTokens = new HashSet<>();
            Set<String> supabaseUrls = new HashSet<>();

            // 1. Check if the request itself is targeting a Supabase host
            if (PatternMatcher.isSupabaseUrl(sourceUrl)) {
                String baseUrl = PatternMatcher.extractSupabaseBaseUrl(sourceUrl);
                if (baseUrl != null) {
                    supabaseUrls.add(baseUrl);
                }
            }

            // 2. Extract JWT tokens from common request headers
            String authHeader = request.headerValue("Authorization");
            if (authHeader != null) {
                jwtTokens.addAll(PatternMatcher.extractJwtTokens(authHeader));
            }

            String apikeyHeader = request.headerValue("Apikey");
            if (apikeyHeader != null) {
                jwtTokens.addAll(PatternMatcher.extractJwtTokens(apikeyHeader));
            }

            String apikeyLowerHeader = request.headerValue("apikey");
            if (apikeyLowerHeader != null && !apikeyLowerHeader.equals(apikeyHeader)) {
                jwtTokens.addAll(PatternMatcher.extractJwtTokens(apikeyLowerHeader));
            }

            String supabaseAuthHeader = request.headerValue("X-Supabase-Auth");
            if (supabaseAuthHeader != null) {
                jwtTokens.addAll(PatternMatcher.extractJwtTokens(supabaseAuthHeader));
            }

            // 3. Scan request body
            String requestBody = request.bodyToString();
            if (requestBody != null && !requestBody.isEmpty()) {
                jwtTokens.addAll(PatternMatcher.extractJwtTokens(requestBody));
                supabaseUrls.addAll(PatternMatcher.extractSupabaseUrls(requestBody));
            }

            // 4. Scan response body (if scannable)
            String responseBody = null;
            if (response != null && isScannable(response)) {
                responseBody = response.bodyToString();
                if (responseBody != null && !responseBody.isEmpty()) {
                    jwtTokens.addAll(PatternMatcher.extractJwtTokens(responseBody));
                    supabaseUrls.addAll(PatternMatcher.extractSupabaseUrls(responseBody));
                }
            }

            if (jwtTokens.isEmpty() && supabaseUrls.isEmpty()) {
                return auditResult(emptyList());
            }

            // 5. Process discovered tokens & URLs
            issues.addAll(processDiscoveredArtifacts(
                baseRequestResponse, jwtTokens, supabaseUrls, sourceUrl, responseBody
            ));
            
        } catch (Exception e) {
            logging.logToError("Passive audit error: " + e.getMessage());
        }
        
        return auditResult(issues);
    }
    
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, 
                                    AuditInsertionPoint auditInsertionPoint) {
        if (!config.isActiveTestingEnabled()) {
            return auditResult(emptyList());
        }
        
        List<AuditIssue> allIssues = new ArrayList<>();

        try {
            // Find Supabase instances related to this request/response
            List<SupabaseInstance> targets = findInstancesForRequest(baseRequestResponse);
            if (targets.isEmpty()) {
                return auditResult(emptyList());
            }

            for (SupabaseInstance instance : targets) {
                if (!instance.hasValidCredentials()) {
                    continue;
                }

                String scanKey = instance.getBaseUrl() + "|" + instance.getJwtToken();
                if (!auditedInstances.add(scanKey)) {
                    // Already audited this instance with this token in this session
                    continue;
                }

                logging.logToOutput("[*] Active scan check auditing RLS on: " + instance.getBaseUrl());
                updateStatus("Active audit: " + extractHost(instance.getBaseUrl()));

                // Run active scan to enumerate and probe tables
                activeScanner.scanInstance(instance);

                // Wire bypass findings into Burp Scanner issue panel
                List<AuditIssue> bypassIssues = createRlsBypassIssues(instance, baseRequestResponse);
                allIssues.addAll(bypassIssues);

                if (!bypassIssues.isEmpty()) {
                    logging.logToOutput(String.format(
                        "[!] Generated %d Burp Scanner issues for %s",
                        bypassIssues.size(), instance.getBaseUrl()
                    ));
                }
            }

        } catch (Exception e) {
            logging.logToError("Active audit error: " + e.getMessage());
        }

        return auditResult(allIssues);
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
        if (instance == null || instance.getTables() == null) {
            return issues;
        }
        
        for (VulnerableTable table : instance.getTables()) {
            if (!table.hasSensitiveData() && !table.isAccessible()) {
                continue;
            }

            // Prefer table's specific proof HttpRequestResponse if available
            HttpRequestResponse issueReqResp = table.getRequestResponse() != null
                ? table.getRequestResponse()
                : requestResponse;

            List<HttpRequestResponse> reqResponses = new ArrayList<>();
            if (issueReqResp != null) {
                reqResponses.add(issueReqResp);
            }
            
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
                reqResponses
            ));
        }
        
        return issues;
    }

    /**
     * Process discovered JWT tokens and Supabase URLs, updating InstanceStore
     * and generating Burp Scanner issues for exposed tokens.
     */
    private List<AuditIssue> processDiscoveredArtifacts(HttpRequestResponse baseRequestResponse,
                                                        Set<String> jwtTokens,
                                                        Set<String> supabaseUrls,
                                                        String sourceUrl,
                                                        String responseBody) {
        List<AuditIssue> issues = new ArrayList<>();

        // Validate tokens
        List<String> validJwts = new ArrayList<>();
        for (String jwt : jwtTokens) {
            String validationError = PatternMatcher.validateSupabaseJwt(jwt);
            if (validationError != null) {
                if (jwt.startsWith("eyJ")) {
                    logging.logToOutput(String.format(
                        "[!] Rejected JWT token %s: %s",
                        sanitizeJwtForLogging(jwt), validationError
                    ));
                }
            } else {
                validJwts.add(jwt);
            }
        }

        // Pair tokens with discovered URLs or infer URL from JWT project ID
        for (String jwt : validJwts) {
            String role = PatternMatcher.extractRoleFromJwt(jwt);
            String projectId = PatternMatcher.extractProjectIdFromJwt(jwt);
            Set<String> matchedUrls = new HashSet<>();

            for (String url : supabaseUrls) {
                if (PatternMatcher.jwtMatchesProject(jwt, url)) {
                    matchedUrls.add(url);
                }
            }

            // If no explicit URL matched, infer project URL
            if (matchedUrls.isEmpty() && projectId != null) {
                matchedUrls.add("https://" + projectId + ".supabase.co");
            }

            for (String targetUrl : matchedUrls) {
                SupabaseInstance instance = instanceStore.addOrUpdate(
                    targetUrl, jwt, sourceUrl, "Scanner detection"
                );

                String host = extractHost(targetUrl);
                boolean isServiceRole = "service_role".equals(role);

                if (isServiceRole) {
                    logging.logToOutput(String.format(
                        "[!!!] CRITICAL: service_role token exposed for %s!", targetUrl
                    ));
                    updateStatus("CRITICAL: " + host + " (service_role exposed!)");
                } else {
                    logging.logToOutput(String.format(
                        "[!] FOUND Supabase instance: %s (role: %s)", targetUrl, role
                    ));
                    updateStatus("Discovered: " + host + " (role: " + role + ")");
                }

                // Build Burp Scanner AuditIssue for exposed token
                AuditIssue issue = buildTokenExposedIssue(
                    baseRequestResponse, jwt, role, targetUrl, matchedUrls, responseBody
                );
                if (issue != null) {
                    issues.add(issue);
                }
            }
        }

        // Also track URLs where no token was found yet
        for (String url : supabaseUrls) {
            if (instanceStore.get(url) == null) {
                instanceStore.addOrUpdate(url, null, sourceUrl, "URL reference");
                updateStatus("Found: " + extractHost(url) + " (no JWT yet)");
            }
        }

        return issues;
    }

    /**
     * Build an AuditIssue for an exposed Supabase JWT token with markers.
     */
    private AuditIssue buildTokenExposedIssue(HttpRequestResponse baseRequestResponse,
                                              String jwt,
                                              String role,
                                              String targetUrl,
                                              Set<String> matchedUrls,
                                              String responseBody) {
        boolean isServiceRole = "service_role".equals(role);
        String issueName = isServiceRole ? ISSUE_NAME_SERVICE_ROLE_EXPOSED : ISSUE_NAME_JWT_EXPOSED;
        AuditIssueSeverity severity = isServiceRole ? AuditIssueSeverity.HIGH : AuditIssueSeverity.HIGH;

        HttpRequestResponse markedRequestResponse = baseRequestResponse;

        // Try highlighting marker in response body
        if (responseBody != null && responseBody.contains(jwt)) {
            List<Marker> markers = findMarkers(responseBody, jwt);
            markedRequestResponse = baseRequestResponse.withResponseMarkers(markers);
        } else {
            // Check request headers/body for marker
            String requestStr = baseRequestResponse.request().toString();
            if (requestStr != null && requestStr.contains(jwt)) {
                List<Marker> markers = findMarkers(requestStr, jwt);
                markedRequestResponse = baseRequestResponse.withRequestMarkers(markers);
            }
        }

        return auditIssue(
            issueName,
            buildJwtExposureDescription(jwt, role, matchedUrls),
            buildJwtRemediationDetail(),
            targetUrl,
            severity,
            AuditIssueConfidence.CERTAIN,
            buildJwtBackground(),
            null,
            severity,
            markedRequestResponse
        );
    }

    /**
     * Identify any Supabase instances associated with the current HTTP request/response.
     */
    private List<SupabaseInstance> findInstancesForRequest(HttpRequestResponse baseRequestResponse) {
        Set<SupabaseInstance> matched = new HashSet<>();
        String reqUrl = baseRequestResponse.request().url();

        // 1. Direct Supabase request URL
        if (PatternMatcher.isSupabaseUrl(reqUrl)) {
            String baseUrl = PatternMatcher.extractSupabaseBaseUrl(reqUrl);
            SupabaseInstance direct = instanceStore.get(baseUrl);
            if (direct != null && direct.hasValidCredentials()) {
                matched.add(direct);
            }
        }

        // 2. Check if request or response contains tokens or project IDs of known instances
        String requestText = baseRequestResponse.request().toString();
        String responseText = baseRequestResponse.response() != null ? baseRequestResponse.response().toString() : "";

        for (SupabaseInstance instance : instanceStore.getAll()) {
            if (!instance.hasValidCredentials()) continue;

            String base = instance.getBaseUrl();
            if (base != null && (requestText.contains(base) || responseText.contains(base))) {
                matched.add(instance);
                continue;
            }

            if (instance.getAnonToken() != null && 
                (requestText.contains(instance.getAnonToken()) || responseText.contains(instance.getAnonToken()))) {
                matched.add(instance);
                continue;
            }

            if (instance.getServiceRoleToken() != null && 
                (requestText.contains(instance.getServiceRoleToken()) || responseText.contains(instance.getServiceRoleToken()))) {
                matched.add(instance);
            }
        }

        return new ArrayList<>(matched);
    }
    
    /**
     * Find markers for highlighting in response or request.
     */
    private List<Marker> findMarkers(String content, String match) {
        List<Marker> markers = new ArrayList<>();
        if (content == null || match == null || match.isEmpty()) {
            return markers;
        }
        int start = 0;
        while ((start = content.indexOf(match, start)) != -1) {
            markers.add(Marker.marker(start, start + match.length()));
            start += match.length();
        }
        return markers;
    }

    /**
     * Map internal severity to Burp severity.
     */
    private AuditIssueSeverity mapSeverity(Severity severity) {
        if (severity == null) {
            return AuditIssueSeverity.INFORMATION;
        }
        return switch (severity) {
            case CRITICAL, HIGH -> AuditIssueSeverity.HIGH;
            case MEDIUM -> AuditIssueSeverity.MEDIUM;
            case LOW -> AuditIssueSeverity.LOW;
            default -> AuditIssueSeverity.INFORMATION;
        };
    }

    /**
     * Check if response content type is scannable for text artifacts.
     */
    private boolean isScannable(HttpResponse response) {
        String contentType = response.headerValue("Content-Type");
        if (contentType == null) {
            return false;
        }
        contentType = contentType.toLowerCase();
        for (String scannable : SCANNABLE_CONTENT_TYPES) {
            if (contentType.contains(scannable)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract hostname from URL for cleaner status messages.
     */
    private String extractHost(String url) {
        try {
            return new URI(url).getHost();
        } catch (Exception e) {
            return url;
        }
    }

    /**
     * Sanitize JWT token for logging.
     */
    private String sanitizeJwtForLogging(String jwt) {
        if (jwt == null || jwt.length() < 30) {
            return "[invalid-jwt]";
        }
        return jwt.substring(0, 20) + "..." + jwt.substring(jwt.length() - 10);
    }

    /**
     * Escape HTML special characters to prevent XSS in issue descriptions.
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

    private String buildJwtExposureDescription(String jwt, String role, Set<String> urls) {
        StringBuilder sb = new StringBuilder();
        sb.append("<p>A Supabase JWT token was found exposed in HTTP traffic.</p>");
        sb.append("<p><b>Token Role:</b> ").append(escapeHtml(role != null ? role : "unknown")).append("</p>");
        sb.append("<p><b>Token (sanitized):</b> ");
        sb.append(escapeHtml(jwt.substring(0, Math.min(20, jwt.length())))).append("...");
        sb.append("</p>");
        if (urls != null && !urls.isEmpty()) {
            sb.append("<p><b>Associated Supabase URLs:</b></p><ul>");
            for (String url : urls) {
                sb.append("<li>").append(escapeHtml(url)).append("</li>");
            }
            sb.append("</ul>");
        }
        if ("service_role".equals(role)) {
            sb.append("<p><b style='color:red;'>CRITICAL WARNING:</b> The exposed token is a <b>service_role</b> token. ");
            sb.append("This token completely bypasses Row Level Security and grants unrestricted administrative database access!</p>");
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
        if (!table.getSensitiveFields().isEmpty()) {
            sb.append("<p><b>Sensitive fields detected:</b></p><ul>");
            for (String field : table.getSensitiveFields()) {
                sb.append("<li>").append(escapeHtml(field)).append("</li>");
            }
            sb.append("</ul>");
        }
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
