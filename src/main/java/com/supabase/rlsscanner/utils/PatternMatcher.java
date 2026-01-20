/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Pattern matching utilities for detection
 */

package com.supabase.rlsscanner.utils;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * Utility class for detecting Supabase URLs, JWT tokens, and sensitive data patterns.
 */
public class PatternMatcher {
    
    // JWT token pattern
    public static final Pattern JWT_PATTERN = Pattern.compile(
        "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"
    );
    
    // Standard Supabase cloud URL pattern
    public static final Pattern SUPABASE_CLOUD_PATTERN = Pattern.compile(
        "https://[a-z0-9-]+\\.supabase\\.co"
    );
    
    // Environment variable patterns for Supabase URLs
    private static final List<Pattern> SUPABASE_ENV_PATTERNS = Arrays.asList(
        Pattern.compile(
            "(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_)?SUPABASE[_-]?URL[\"']?\\s*[:=]\\s*[\"']?(https://[^\"'\\s,}]+)",
            Pattern.CASE_INSENSITIVE
        ),
        Pattern.compile(
            "(?:[\"']?)(?:supabaseUrl|supabase_url|supabaseURL)(?:[\"']?\\s*[:=]\\s*[\"']?)(https://[^\"'\\s,}]+)",
            Pattern.CASE_INSENSITIVE
        ),
        Pattern.compile(
            "(?:supabase|SUPABASE)[\"'\\s:=]+(https://[^\"'\\s,}]+)",
            Pattern.CASE_INSENSITIVE
        )
    );
    
    // Sensitive data patterns in values
    public static final Pattern EMAIL_PATTERN = Pattern.compile(
        "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
    );
    
    public static final Pattern PHONE_PATTERN = Pattern.compile(
        "[+]?[(]?[0-9]{1,4}[)]?[-\\s.]?[(]?[0-9]{1,4}[)]?[-\\s.]?[0-9]{1,9}"
    );
    
    public static final Pattern CREDIT_CARD_PATTERN = Pattern.compile(
        "\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b"
    );
    
    /**
     * Extract all JWT tokens from content.
     */
    public static List<String> extractJwtTokens(String content) {
        List<String> tokens = new ArrayList<>();
        if (content == null) return tokens;
        
        Matcher matcher = JWT_PATTERN.matcher(content);
        while (matcher.find()) {
            tokens.add(matcher.group());
        }
        return tokens;
    }
    
    /**
     * Extract all Supabase URLs from content.
     */
    public static Set<String> extractSupabaseUrls(String content) {
        Set<String> urls = new HashSet<>();
        if (content == null) return urls;
        
        // Extract standard .supabase.co URLs
        Matcher cloudMatcher = SUPABASE_CLOUD_PATTERN.matcher(content);
        while (cloudMatcher.find()) {
            urls.add(normalizeUrl(cloudMatcher.group()));
        }
        
        // Extract URLs from environment variable patterns
        for (Pattern pattern : SUPABASE_ENV_PATTERNS) {
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                String url = matcher.group(1);
                if (url != null && url.startsWith("https://")) {
                    urls.add(normalizeUrl(cleanUrl(url)));
                }
            }
        }
        
        return urls;
    }

    /**
     * Check if a URL is a Supabase URL (cloud or self-hosted pattern).
     */
    public static boolean isSupabaseUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        // Check for standard .supabase.co pattern
        if (SUPABASE_CLOUD_PATTERN.matcher(url).find()) {
            return true;
        }
        // Check for common Supabase path patterns (e.g., /rest/v1/, /auth/v1/)
        return url.contains("/rest/v1") || url.contains("/auth/v1") ||
               url.contains("/storage/v1") || url.contains("/realtime/v1");
    }

    /**
     * Extract the base Supabase URL from a full URL.
     * E.g., "https://abc.supabase.co/rest/v1/users" -> "https://abc.supabase.co"
     */
    public static String extractSupabaseBaseUrl(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        try {
            java.net.URI uri = new java.net.URI(url);
            String host = uri.getHost();
            if (host != null) {
                // Check if it's a Supabase cloud URL
                if (host.endsWith(".supabase.co")) {
                    int port = uri.getPort();
                    String scheme = uri.getScheme();
                    if (port > 0 && port != 443 && port != 80) {
                        return scheme + "://" + host + ":" + port;
                    }
                    return scheme + "://" + host;
                }
                // For self-hosted, check if path contains Supabase patterns
                String path = uri.getPath();
                if (path != null && (path.contains("/rest/v1") || path.contains("/auth/v1"))) {
                    int port = uri.getPort();
                    String scheme = uri.getScheme();
                    if (port > 0 && port != 443 && port != 80) {
                        return scheme + "://" + host + ":" + port;
                    }
                    return scheme + "://" + host;
                }
            }
        } catch (Exception e) {
            // Fall back to regex
            Matcher matcher = SUPABASE_CLOUD_PATTERN.matcher(url);
            if (matcher.find()) {
                return matcher.group();
            }
        }
        return null;
    }

    /**
     * Validate JWT structure and signature with detailed reason.
     * Returns null if valid, or a string describing why it's invalid.
     */
    public static String validateJwtStructure(String jwt) {
        if (jwt == null || jwt.isEmpty()) {
            return "JWT is null or empty";
        }

        try {
            // Try to decode the JWT - this will fail if the structure is invalid
            DecodedJWT decodedJWT = JWT.decode(jwt);

            // Verify it has all required parts
            if (decodedJWT.getHeader() == null ||
                decodedJWT.getPayload() == null ||
                decodedJWT.getSignature() == null) {
                return "JWT is missing required parts (header, payload, or signature)";
            }

            // Verify the signature using basic heuristics
            String signature = decodedJWT.getSignature();

            // Check 1: Signature should be base64url encoded (only alphanumeric, -, _)
            if (!signature.matches("^[A-Za-z0-9_-]+$")) {
                return "JWT signature is not valid base64url encoding";
            }

            // Check 2: Minimum length check - HMAC-SHA256 signatures are typically 43 chars
            // We'll be lenient and accept anything >= 32 chars
            if (signature.length() < 32) {
                return "JWT signature is too short (less than 32 characters)";
            }

            return null; // Valid
        } catch (Exception e) {
            return "JWT structure is invalid: " + e.getMessage();
        }
    }

    /**
     * Validate JWT structure and signature.
     * This checks if the JWT has a valid structure (3 parts) and can be decoded.
     * We don't verify the signature with a secret since we don't know the secret,
     * but we validate that the JWT is properly formed and can be decoded.
     */
    public static boolean isValidJwtStructure(String jwt) {
        return validateJwtStructure(jwt) == null;
    }

    /**
     * Validate if a JWT is a valid Supabase JWT with detailed reason.
     * Returns null if valid, or a string describing why it's invalid.
     */
    public static String validateSupabaseJwt(String jwt) {
        if (jwt == null || !jwt.startsWith("eyJ")) {
            return "JWT does not start with 'eyJ' (not a valid JWT format)";
        }

        // First validate JWT structure
        String structureError = validateJwtStructure(jwt);
        if (structureError != null) {
            return structureError;
        }

        try {
            String decoded = decodeJwtPayload(jwt);
            if (decoded == null) {
                return "Failed to decode JWT payload";
            }

            // Must have iss="supabase"
            if (!decoded.contains("\"iss\":\"supabase\"")) {
                // Try to extract the actual issuer
                String iss = extractFieldFromPayload(decoded, "iss");
                if (iss != null) {
                    return "JWT issuer is '" + iss + "' (expected 'supabase')";
                }
                return "JWT does not have 'supabase' as the issuer";
            }

            // Must have ref field
            if (!decoded.contains("\"ref\":")) {
                return "JWT does not contain a 'ref' field (project ID)";
            }

            // Must have role of "anon" or "service_role"
            String role = extractRoleFromJwt(jwt);
            if (!"anon".equals(role) && !"service_role".equals(role)) {
                if (role != null) {
                    return "JWT role is '" + role + "' (expected 'anon' or 'service_role')";
                }
                return "JWT does not have role 'anon' or 'service_role'";
            }

            return null; // Valid

        } catch (Exception e) {
            return "Error validating JWT: " + e.getMessage();
        }
    }

    /**
     * Extract a field value from decoded JWT payload.
     */
    private static String extractFieldFromPayload(String payload, String fieldName) {
        try {
            String pattern = "\"" + fieldName + "\":\"([^\"]+)\"";
            java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(pattern).matcher(payload);
            if (matcher.find()) {
                return matcher.group(1);
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    /**
     * Check if a JWT token appears to be a Supabase token.
     * Supabase JWTs must have:
     * - Valid JWT structure and signature format
     * - iss="supabase"
     * - contain a "ref" claim
     * - role must be "anon" or "service_role"
     */
    public static boolean isSupabaseJwt(String jwt) {
        return validateSupabaseJwt(jwt) == null;
    }

    /**
     * Decode JWT payload (base64url) to string.
     */
    public static String decodeJwtPayload(String jwt) {
        if (jwt == null || !jwt.startsWith("eyJ")) return null;

        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) return null;

            // Decode the payload (base64url)
            String payload = parts[1];
            // Convert base64url to base64
            payload = payload.replace('-', '+').replace('_', '/');
            // Add padding if needed
            while (payload.length() % 4 != 0) {
                payload += "=";
            }
            return new String(Base64.getDecoder().decode(payload));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extract the project ID (ref) from a Supabase JWT.
     * Returns null if not a valid Supabase JWT.
     */
    public static String extractProjectIdFromJwt(String jwt) {
        String decoded = decodeJwtPayload(jwt);
        if (decoded == null) return null;

        // Check iss is "supabase"
        if (!decoded.contains("\"iss\":\"supabase\"")) {
            return null;
        }

        // Extract ref value using simple string parsing
        // Format: "ref":"projectid"
        int refIndex = decoded.indexOf("\"ref\":\"");
        if (refIndex == -1) return null;

        int start = refIndex + 7; // length of "ref":"
        int end = decoded.indexOf("\"", start);
        if (end == -1) return null;

        return decoded.substring(start, end);
    }

    /**
     * Extract the project ID from a Supabase URL.
     * URL format: https://<projectid>.supabase.co
     */
    public static String extractProjectIdFromUrl(String url) {
        if (url == null) return null;

        // Match pattern: https://<projectid>.supabase.co
        Matcher matcher = Pattern.compile("https://([a-z0-9-]+)\\.supabase\\.co").matcher(url);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Check if a JWT belongs to a specific Supabase project URL.
     * Validates iss="supabase" and ref matches the project ID from URL.
     */
    public static boolean jwtMatchesProject(String jwt, String supabaseUrl) {
        String jwtProjectId = extractProjectIdFromJwt(jwt);
        String urlProjectId = extractProjectIdFromUrl(supabaseUrl);

        if (jwtProjectId == null || urlProjectId == null) {
            return false;
        }

        return jwtProjectId.equals(urlProjectId);
    }

    /**
     * Extract the role from a Supabase JWT.
     * Returns null if not found.
     */
    public static String extractRoleFromJwt(String jwt) {
        String decoded = decodeJwtPayload(jwt);
        if (decoded == null) return null;

        // Extract role value: "role":"anon" or "role":"service_role"
        int roleIndex = decoded.indexOf("\"role\":\"");
        if (roleIndex == -1) return null;

        int start = roleIndex + 8; // length of "role":"
        int end = decoded.indexOf("\"", start);
        if (end == -1) return null;

        return decoded.substring(start, end);
    }

    /**
     * Check if a JWT is a service_role token (CRITICAL - should never be exposed).
     */
    public static boolean isServiceRoleJwt(String jwt) {
        String role = extractRoleFromJwt(jwt);
        return "service_role".equals(role);
    }

    /**
     * Normalize URL by removing trailing slashes.
     */
    private static String normalizeUrl(String url) {
        if (url == null) return null;
        return url.replaceAll("/+$", "");
    }

    /**
     * Clean URL by removing trailing quotes, commas, brackets.
     */
    private static String cleanUrl(String url) {
        if (url == null) return null;
        return url.replaceAll("[\"',)}\\]]+$", "").trim();
    }

    private PatternMatcher() {
        // Utility class
    }
}

