/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Passive scanner for detecting Supabase instances in HTTP traffic
 */

package com.supabase.rlsscanner.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.supabase.rlsscanner.core.InstanceStore;
import com.supabase.rlsscanner.core.ScannerConfig;
import com.supabase.rlsscanner.models.Severity;
import com.supabase.rlsscanner.models.SupabaseInstance;
import com.supabase.rlsscanner.utils.PatternMatcher;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * HTTP handler that passively scans HTTP traffic for Supabase JWT tokens and URLs.
 */
public class PassiveScanner implements HttpHandler {

    private final MontoyaApi api;
    private final Logging logging;
    private final ScannerConfig config;
    private final InstanceStore instanceStore;
    private ActiveScanner activeScanner;
    private Consumer<String> statusListener;

    // Track which instances have been auto-enumerated to avoid duplicates
    private final Set<String> autoEnumeratedInstances = ConcurrentHashMap.newKeySet();

    // Content types to scan
    private static final Set<String> SCANNABLE_CONTENT_TYPES = Set.of(
        "text/html",
        "application/javascript",
        "text/javascript",
        "application/json",
        "text/plain"
    );

    public PassiveScanner(MontoyaApi api, ScannerConfig config, InstanceStore instanceStore) {
        this.api = api;
        this.logging = api.logging();
        this.config = config;
        this.instanceStore = instanceStore;
    }

    /**
     * Set the active scanner for auto-enumeration.
     * Must be called after ActiveScanner is initialized.
     */
    public void setActiveScanner(ActiveScanner activeScanner) {
        this.activeScanner = activeScanner;
    }

    /**
     * Set a listener to receive status updates.
     */
    public void setStatusListener(Consumer<String> listener) {
        this.statusListener = listener;
    }

    /**
     * Send status update to listener.
     */
    private void updateStatus(String message) {
        if (statusListener != null) {
            statusListener.accept(message);
        }
    }

    /**
     * Clear all cached state (auto-enumeration tracking).
     * Should be called when the user clears all instances.
     */
    public void clear() {
        autoEnumeratedInstances.clear();
        logging.logToOutput("[*] Cleared passive scanner state");
    }
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        if (config.isPassiveScanningEnabled()) {
            try {
                analyzeRequest(requestToBeSent);
            } catch (Exception e) {
                logging.logToError("Error in passive scanner (request): " + e.getMessage());
            }
        }
        // We don't modify requests, just pass them through
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    /**
     * Analyze an HTTP request for Supabase JWT tokens in headers.
     * This catches tokens in Authorization, Apikey, and other common header patterns.
     */
    private void analyzeRequest(HttpRequestToBeSent request) {
        String sourceUrl = request.url();
        Set<String> jwtTokens = new HashSet<>();
        Set<String> supabaseUrls = new HashSet<>();

        // Check if this is a request to a Supabase URL
        if (PatternMatcher.isSupabaseUrl(sourceUrl)) {
            // Extract base URL from request URL
            String baseUrl = PatternMatcher.extractSupabaseBaseUrl(sourceUrl);
            if (baseUrl != null) {
                supabaseUrls.add(baseUrl);
            }
        }

        // Extract JWT tokens from common headers
        // 1. Authorization: Bearer <token>
        String authHeader = request.headerValue("Authorization");
        if (authHeader != null) {
            List<String> tokens = PatternMatcher.extractJwtTokens(authHeader);
            jwtTokens.addAll(tokens);
        }

        // 2. Apikey: <token> (Supabase specific)
        String apikeyHeader = request.headerValue("Apikey");
        if (apikeyHeader != null) {
            List<String> tokens = PatternMatcher.extractJwtTokens(apikeyHeader);
            jwtTokens.addAll(tokens);
        }

        // 3. apikey: <token> (lowercase variant)
        String apikeyLowerHeader = request.headerValue("apikey");
        if (apikeyLowerHeader != null && !apikeyLowerHeader.equals(apikeyHeader)) {
            List<String> tokens = PatternMatcher.extractJwtTokens(apikeyLowerHeader);
            jwtTokens.addAll(tokens);
        }

        // 4. X-Supabase-Auth or similar custom headers
        String supabaseAuthHeader = request.headerValue("X-Supabase-Auth");
        if (supabaseAuthHeader != null) {
            List<String> tokens = PatternMatcher.extractJwtTokens(supabaseAuthHeader);
            jwtTokens.addAll(tokens);
        }

        // 5. Also scan request body for JWTs (e.g., in JSON payloads)
        String requestBody = request.bodyToString();
        if (requestBody != null && !requestBody.isEmpty()) {
            List<String> bodyTokens = PatternMatcher.extractJwtTokens(requestBody);
            jwtTokens.addAll(bodyTokens);

            // Also check for Supabase URLs in request body
            Set<String> bodyUrls = PatternMatcher.extractSupabaseUrls(requestBody);
            supabaseUrls.addAll(bodyUrls);
        }

        // Process discovered tokens
        processDiscoveredTokens(jwtTokens, supabaseUrls, sourceUrl, "HTTP Request Headers");
    }

    /**
     * Process discovered JWT tokens and associate with Supabase URLs.
     */
    private void processDiscoveredTokens(Set<String> jwtTokens, Set<String> supabaseUrls,
                                          String sourceUrl, String context) {
        // Filter for valid Supabase JWTs
        List<String> supabaseJwts = new ArrayList<>();
        for (String jwt : jwtTokens) {
            String validationError = PatternMatcher.validateSupabaseJwt(jwt);

            if (validationError != null) {
                // Log why this JWT was rejected (only if it looks like a JWT)
                if (jwt.startsWith("eyJ")) {
                    String sanitizedJwt = sanitizeJwtForLogging(jwt);
                    logging.logToOutput(String.format(
                        "[!] Rejected JWT token %s: %s",
                        sanitizedJwt,
                        validationError
                    ));
                }
            } else if (!instanceStore.hasSeenJwt(jwt)) {
                supabaseJwts.add(jwt);
            }
        }

        if (supabaseJwts.isEmpty()) {
            return;
        }

        // If we have both URLs and JWTs, pair them by project ID
        if (!supabaseUrls.isEmpty()) {
            for (String url : supabaseUrls) {
                for (String jwt : supabaseJwts) {
                    if (!PatternMatcher.jwtMatchesProject(jwt, url)) {
                        continue;
                    }

                    String role = PatternMatcher.extractRoleFromJwt(jwt);
                    if (!"anon".equals(role) && !"service_role".equals(role)) {
                        continue;
                    }

                    SupabaseInstance instance = instanceStore.addOrUpdate(url, jwt, sourceUrl, context);

                    if (instance != null && instance.hasValidCredentials()) {
                        String host = extractHost(url);

                        if ("service_role".equals(role)) {
                            logging.logToOutput(String.format(
                                "[!!!] CRITICAL: service_role token exposed for %s! (from %s)", url, context
                            ));
                            updateStatus("CRITICAL: " + host + " (service_role exposed!)");
                        } else {
                            logging.logToOutput(String.format(
                                "[!] FOUND Supabase instance: %s (role: %s) from %s", url, role, context
                            ));
                            updateStatus("Discovered: " + host + " (role: " + role + ")");
                        }

                        triggerAutoEnumeration(instance);
                    }
                }
            }
        } else {
            // No URLs found - try to match JWTs to existing instances or infer URL from JWT
            for (String jwt : supabaseJwts) {
                String jwtProjectId = PatternMatcher.extractProjectIdFromJwt(jwt);
                if (jwtProjectId == null) {
                    continue;
                }

                String role = PatternMatcher.extractRoleFromJwt(jwt);
                if (!"anon".equals(role) && !"service_role".equals(role)) {
                    continue;
                }

                // Try to match to existing instances
                boolean matched = false;
                for (SupabaseInstance existing : instanceStore.getAll()) {
                    boolean needsToken = false;
                    if ("anon".equals(role) && !existing.hasAnonToken()) {
                        needsToken = true;
                    } else if ("service_role".equals(role) && !existing.hasServiceRoleToken()) {
                        needsToken = true;
                    }

                    if (needsToken && PatternMatcher.jwtMatchesProject(jwt, existing.getBaseUrl())) {
                        SupabaseInstance updated = instanceStore.addOrUpdate(
                            existing.getBaseUrl(), jwt, sourceUrl, context + " (matched by project ID)"
                        );

                        if (updated != null && updated.hasValidCredentials()) {
                            String host = extractHost(existing.getBaseUrl());
                            if ("service_role".equals(role)) {
                                logging.logToOutput(String.format(
                                    "[!!!] CRITICAL: service_role token matched to %s!", existing.getBaseUrl()
                                ));
                                updateStatus("CRITICAL: " + host + " (service_role exposed!)");
                            } else {
                                updateStatus("JWT matched: " + host + " (role: " + role + ")");
                            }
                            triggerAutoEnumeration(updated);
                        }
                        matched = true;
                    }
                }

                // If no match found, infer the Supabase URL from JWT project ID
                if (!matched) {
                    String inferredUrl = "https://" + jwtProjectId + ".supabase.co";
                    SupabaseInstance instance = instanceStore.addOrUpdate(
                        inferredUrl, jwt, sourceUrl, context + " (URL inferred from JWT project ID)"
                    );

                    if (instance != null && instance.hasValidCredentials()) {
                        String host = extractHost(inferredUrl);
                        if ("service_role".equals(role)) {
                            logging.logToOutput(String.format(
                                "[!!!] CRITICAL: service_role token found, inferred URL: %s", inferredUrl
                            ));
                            updateStatus("CRITICAL: " + host + " (service_role exposed!)");
                        } else {
                            logging.logToOutput(String.format(
                                "[!] FOUND Supabase JWT (inferred URL: %s, role: %s) from %s",
                                inferredUrl, role, context
                            ));
                            updateStatus("Discovered: " + host + " (role: " + role + ", inferred)");
                        }
                        triggerAutoEnumeration(instance);
                    }
                }
            }
        }
    }
    
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (!config.isPassiveScanningEnabled()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        
        try {
            analyzeResponse(responseReceived);
        } catch (Exception e) {
            logging.logToError("Error in passive scanner: " + e.getMessage());
        }
        
        return ResponseReceivedAction.continueWith(responseReceived);
    }
    
    /**
     * Analyze an HTTP response for Supabase artifacts.
     */
    private void analyzeResponse(HttpResponseReceived response) {
        // Only analyze successful responses
        if (response.statusCode() < 200 || response.statusCode() >= 400) {
            return;
        }
        
        // Check content type
        if (!isScannable(response)) {
            return;
        }
        
        String body = response.bodyToString();
        if (body == null || body.isEmpty()) {
            return;
        }
        
        String sourceUrl = response.initiatingRequest().url();
        
        // Extract Supabase URLs
        Set<String> supabaseUrls = PatternMatcher.extractSupabaseUrls(body);
        
        // Extract JWT tokens
        List<String> jwtTokens = PatternMatcher.extractJwtTokens(body);

        // Filter for likely Supabase JWTs
        List<String> supabaseJwts = new ArrayList<>();
        for (String jwt : jwtTokens) {
            // Validate the JWT and log rejection reason if invalid
            String validationError = PatternMatcher.validateSupabaseJwt(jwt);

            if (validationError != null) {
                // Log why this JWT was rejected
                String sanitizedJwt = sanitizeJwtForLogging(jwt);
                logging.logToOutput(String.format(
                    "[!] Rejected JWT token %s: %s",
                    sanitizedJwt,
                    validationError
                ));
            } else if (!instanceStore.hasSeenJwt(jwt)) {
                // Valid Supabase JWT that we haven't seen before
                supabaseJwts.add(jwt);
            }
        }
        
        // If we found both URLs and tokens, pair them up based on matching project ID
        if (!supabaseUrls.isEmpty() && !supabaseJwts.isEmpty()) {
            for (String url : supabaseUrls) {
                for (String jwt : supabaseJwts) {
                    // Only pair JWT with URL if the project IDs match
                    if (!PatternMatcher.jwtMatchesProject(jwt, url)) {
                        continue;
                    }

                    String role = PatternMatcher.extractRoleFromJwt(jwt);

                    // Only accept anon or service_role tokens (already validated in isSupabaseJwt)
                    if (!"anon".equals(role) && !"service_role".equals(role)) {
                        continue;
                    }

                    SupabaseInstance instance = instanceStore.addOrUpdate(
                        url, jwt, sourceUrl, getContext(response)
                    );

                    if (instance != null && instance.hasValidCredentials()) {
                        String host = extractHost(url);

                        // Check for service_role token - CRITICAL finding
                        if ("service_role".equals(role)) {
                            logging.logToOutput(String.format(
                                "[!!!] CRITICAL: service_role token exposed for %s!", url
                            ));
                            updateStatus("CRITICAL: " + host + " (service_role exposed!)");
                        } else {
                            logging.logToOutput(String.format(
                                "[!] FOUND Supabase instance: %s (role: %s)", url, role
                            ));
                            updateStatus("Discovered: " + host + " (role: " + role + ")");
                        }

                        // Trigger auto-enumeration if enabled
                        triggerAutoEnumeration(instance);
                    }
                }
            }
        } else if (!supabaseUrls.isEmpty()) {
            // Found URLs but no tokens - only log once per unique URL
            for (String url : supabaseUrls) {
                SupabaseInstance existing = instanceStore.get(url);
                if (existing == null) {
                    instanceStore.addOrUpdate(url, null, sourceUrl, getContext(response));
                    String host = extractHost(url);
                    updateStatus("Found: " + host + " (no JWT yet)");
                }
            }
        } else if (!supabaseJwts.isEmpty()) {
            // Found tokens but no URLs - try to match to existing instances by project ID
            for (String jwt : supabaseJwts) {
                String jwtProjectId = PatternMatcher.extractProjectIdFromJwt(jwt);
                if (jwtProjectId == null) {
                    continue;
                }

                String role = PatternMatcher.extractRoleFromJwt(jwt);

                // Only accept anon or service_role tokens
                if (!"anon".equals(role) && !"service_role".equals(role)) {
                    continue;
                }

                // Try to associate with matching existing instances (by project ID)
                for (SupabaseInstance existing : instanceStore.getAll()) {
                    // Check if we need to add this token (either no tokens yet, or missing this role)
                    boolean needsToken = false;
                    if ("anon".equals(role) && !existing.hasAnonToken()) {
                        needsToken = true;
                    } else if ("service_role".equals(role) && !existing.hasServiceRoleToken()) {
                        needsToken = true;
                    }

                    if (needsToken && PatternMatcher.jwtMatchesProject(jwt, existing.getBaseUrl())) {
                        SupabaseInstance updated = instanceStore.addOrUpdate(
                            existing.getBaseUrl(), jwt, sourceUrl, "JWT matched by project ID"
                        );

                        // Trigger auto-enumeration if enabled
                        if (updated != null && updated.hasValidCredentials()) {
                            String host = extractHost(existing.getBaseUrl());

                            // Check for service_role token - CRITICAL
                            if ("service_role".equals(role)) {
                                logging.logToOutput(String.format(
                                    "[!!!] CRITICAL: service_role token exposed for %s!", existing.getBaseUrl()
                                ));
                                updateStatus("CRITICAL: " + host + " (service_role exposed!)");
                            } else {
                                updateStatus("JWT matched: " + host + " (role: " + role + ")");
                            }

                            triggerAutoEnumeration(updated);
                        }
                    }
                }
            }
        }
    }

    /**
     * Extract hostname from URL for cleaner status messages.
     */
    private String extractHost(String url) {
        try {
            return new java.net.URI(url).getHost();
        } catch (Exception e) {
            return url;
        }
    }

    /**
     * Trigger auto-enumeration for a discovered instance if enabled.
     * Enumerates both anon and service_role tokens if available.
     */
    private void triggerAutoEnumeration(SupabaseInstance instance) {
        if (!config.isAutoEnumerateEnabled()) {
            return;
        }

        if (activeScanner == null) {
            logging.logToError("[!] Auto-enumerate enabled but ActiveScanner not set");
            return;
        }

        // Check if we've already auto-enumerated this instance with each token type
        // We need to scan separately for anon and service_role tokens
        boolean shouldScan = false;

        if (instance.hasAnonToken()) {
            String anonKey = instance.getBaseUrl() + "|anon|" + instance.getAnonToken();
            if (!autoEnumeratedInstances.contains(anonKey)) {
                autoEnumeratedInstances.add(anonKey);
                shouldScan = true;
            }
        }

        if (instance.hasServiceRoleToken()) {
            String serviceKey = instance.getBaseUrl() + "|service_role|" + instance.getServiceRoleToken();
            if (!autoEnumeratedInstances.contains(serviceKey)) {
                autoEnumeratedInstances.add(serviceKey);
                shouldScan = true;
            }
        }

        if (!shouldScan) {
            return;
        }

        logging.logToOutput(String.format(
            "[*] Auto-enumerating instance: %s (tokens: %s)",
            instance.getBaseUrl(),
            instance.getJwtRole()
        ));

        // Run scan in background thread to not block HTTP traffic
        activeScanner.scanInstance(instance);
    }
    
    /**
     * Check if response should be scanned based on content type.
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
     * Sanitize JWT token for logging (show first 20 and last 10 chars).
     */
    private String sanitizeJwtForLogging(String jwt) {
        if (jwt == null || jwt.length() < 30) {
            return "[invalid-jwt]";
        }
        return jwt.substring(0, 20) + "..." + jwt.substring(jwt.length() - 10);
    }
    
    /**
     * Get context information about where the discovery was made.
     */
    private String getContext(HttpResponseReceived response) {
        String contentType = response.headerValue("Content-Type");
        return String.format("Content-Type: %s, Status: %d", 
            contentType != null ? contentType : "unknown", 
            response.statusCode()
        );
    }
}

