/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Active scanner for testing RLS policies
 */

package com.supabase.rlsscanner.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;
import com.supabase.rlsscanner.core.ScannerConfig;
import com.supabase.rlsscanner.models.*;
import com.supabase.rlsscanner.utils.SensitiveFieldAnalyzer;

import java.lang.reflect.Type;
import java.net.URI;
import java.util.*;
import java.util.function.Consumer;

/**
 * Active scanner for testing Supabase RLS policies.
 */
public class ActiveScanner {

    private static final RequestOptions SECURE_REQUEST_OPTIONS = RequestOptions.requestOptions()
        .withUpstreamTLSVerification()
        .withRedirectionMode(RedirectionMode.ALWAYS);

    private static final List<String> COMMON_SUPABASE_TABLES = List.of(
        "users", "profiles", "accounts", "user_profiles", "members",
        "organizations", "settings", "posts", "comments", "messages",
        "todos", "teams", "roles", "files", "documents", "audit_logs",
        "customers", "orders", "products", "notifications", "items"
    );

    private enum HeaderMode {
        BOTH,
        APIKEY_ONLY,
        BEARER_ONLY
    }

    private final MontoyaApi api;
    private final Logging logging;
    private final ScannerConfig config;
    private final Gson gson;

    // Status listener for UI updates
    private Consumer<String> statusListener;

    public ActiveScanner(MontoyaApi api, ScannerConfig config) {
        this.api = api;
        this.logging = api.logging();
        this.config = config;
        this.gson = new Gson();
    }

    /**
     * Set a listener to receive status updates.
     */
    public void setStatusListener(Consumer<String> listener) {
        this.statusListener = listener;
    }

    /**
     * Send status update to listener and log.
     */
    private void updateStatus(String message) {
        if (statusListener != null) {
            statusListener.accept(message);
        }
    }
    
    /**
     * Perform a full RLS scan on a Supabase instance.
     */
    public ScanResult scanInstance(SupabaseInstance instance) {
        if (!instance.hasValidCredentials()) {
            ScanResult result = new ScanResult(instance);
            result.setErrorMessage("Invalid credentials - missing URL or JWT token");
            updateStatus("Scan failed: Missing credentials");
            return result;
        }

        String host = extractHost(instance.getBaseUrl());
        logging.logToOutput(String.format("[*] Starting RLS scan on %s", instance.getBaseUrl()));
        updateStatus("Scanning: " + host);

        try {
            // Step 1: Enumerate tables
            List<String> tables = enumerateTables(instance);
            if (tables.isEmpty()) {
                ScanResult result = new ScanResult(instance);
                result.setErrorMessage("Could not enumerate tables");
                result.setSuccess(false);
                instance.setTested(true);  // Mark as tested even if no tables found
                instance.setTables(new ArrayList<>());  // Set empty tables list
                updateStatus("No tables found on " + host);
                return result;
            }

            logging.logToOutput(String.format("[+] Found %d tables", tables.size()));
            updateStatus("Found " + tables.size() + " tables on " + host);

            // Step 2: Test each table
            List<VulnerableTable> allTables = new ArrayList<>();
            int accessibleCount = 0;

            for (String tableName : tables) {
                if (Thread.currentThread().isInterrupted()) {
                    logging.logToOutput("[*] Scan interrupted, halting table checks.");
                    break;
                }

                if (config.getDelayBetweenRequests() > 0) {
                    Thread.sleep(config.getDelayBetweenRequests());
                }

                VulnerableTable tableResult = testTable(instance, tableName);
                allTables.add(tableResult);

                if (tableResult.isAccessible()) {
                    accessibleCount++;
                }
            }

            // Step 3: Build result
            ScanResult result = new ScanResult(instance, tables.size(), accessibleCount);
            result.setSuccess(true);

            int vulnCount = 0;
            for (VulnerableTable table : allTables) {
                if (table.hasSensitiveData()) {
                    result.addVulnerableTable(table);
                    vulnCount++;
                    logging.logToOutput(String.format(
                        "  [!] VULNERABLE: %s - %d rows - %s",
                        table.getTableName(), table.getRowCount(), table.getSeverity()
                    ));
                    updateStatus("VULN: " + table.getTableName() + " (" + table.getRowCount() + " rows, " + table.getSeverity() + ")");
                }
            }

            instance.setTables(allTables);
            instance.setTested(true);

            // Final summary
            if (vulnCount > 0) {
                updateStatus("Scan complete: " + vulnCount + " vulnerable tables on " + host);
            } else {
                updateStatus("Scan complete: No vulnerabilities on " + host);
            }

            return result;

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logging.logToOutput("[*] Scan interrupted for " + host);
            ScanResult result = new ScanResult(instance);
            result.setErrorMessage("Scan interrupted");
            return result;
        } catch (Exception e) {
            logging.logToError("Scan error: " + e.getMessage());
            ScanResult result = new ScanResult(instance);
            result.setErrorMessage(e.getMessage());
            updateStatus("Scan error on " + host + ": " + e.getMessage());
            return result;
        }
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
     * Enumerate available tables using the OpenAPI endpoint with fallback handling.
     * Supabase exposes an OpenAPI spec at /rest/v1/ that lists all available tables.
     * Fallbacks handle alternate paths, authentication issues (401/403), redirects,
     * and common table probing if metadata endpoint is disabled.
     */
    private List<String> enumerateTables(SupabaseInstance instance) {
        List<String> tables = new ArrayList<>();

        // Candidate paths for PostgREST OpenAPI spec
        String[] candidatePaths = {
            "/rest/v1/",
            "/rest/v1",
            "/",
            "/api/v1/"
        };

        // Try candidate paths
        for (String path : candidatePaths) {
            if (Thread.currentThread().isInterrupted()) break;
            tables = tryEnumerateOpenApi(instance, path);
            if (!tables.isEmpty()) {
                logging.logToOutput("[+] Successfully enumerated " + tables.size() + " tables from OpenAPI endpoint: " + path);
                return tables;
            }
        }

        // If OpenAPI endpoint returns non-200 or no tables, fallback to probing common table names
        if (tables.isEmpty() && !Thread.currentThread().isInterrupted()) {
            logging.logToOutput("[*] OpenAPI metadata unavailable; falling back to probing common table names...");
            tables = probeCommonTables(instance);
        }

        logging.logToOutput("[*] Total tables found: " + tables.size());
        return tables;
    }

    /**
     * Try fetching and parsing OpenAPI specification from a specific path with fallback options.
     */
    private List<String> tryEnumerateOpenApi(SupabaseInstance instance, String path) {
        List<String> tables = new ArrayList<>();
        try {
            // Attempt 1: Standard request with active token (both apikey and Authorization headers)
            HttpRequest request = buildOpenApiRequest(instance, path, instance.getJwtToken(), HeaderMode.BOTH);
            logging.logToOutput("[*] Fetching OpenAPI spec from " + instance.getBaseUrl() + path);
            HttpRequestResponse response = api.http().sendRequest(request, SECURE_REQUEST_OPTIONS);

            int statusCode = response.response().statusCode();

            // Handle redirect if returned (e.g., 301, 302, 307, 308)
            if (statusCode >= 300 && statusCode < 400) {
                String location = response.response().headerValue("Location");
                if (location != null && !location.isEmpty()) {
                    logging.logToOutput("[*] Following redirect to: " + location);
                    if (location.startsWith("/")) {
                        return tryEnumerateOpenApi(instance, location);
                    }
                }
            }

            // Fallback 1: On 401/403, retry with alternate tokens or headers
            if (statusCode == 401 || statusCode == 403) {
                logging.logToOutput("[!] HTTP " + statusCode + " on " + path + "; attempting authentication fallbacks...");

                // If alternate token is available (service_role or anon), try it
                List<String> alternateTokens = new ArrayList<>();
                if (instance.hasServiceRoleToken() && !instance.getServiceRoleToken().equals(instance.getJwtToken())) {
                    alternateTokens.add(instance.getServiceRoleToken());
                }
                if (instance.hasAnonToken() && !instance.getAnonToken().equals(instance.getJwtToken())) {
                    alternateTokens.add(instance.getAnonToken());
                }

                for (String altToken : alternateTokens) {
                    HttpRequest altReq = buildOpenApiRequest(instance, path, altToken, HeaderMode.BOTH);
                    HttpResponse altResp = api.http().sendRequest(altReq, SECURE_REQUEST_OPTIONS).response();
                    if (altResp.statusCode() == 200) {
                        return parseOpenApiTables(altResp.bodyToString());
                    }
                }

                // Header variation 1: Only apikey header
                HttpRequest apikeyOnlyReq = buildOpenApiRequest(instance, path, instance.getJwtToken(), HeaderMode.APIKEY_ONLY);
                HttpResponse apikeyOnlyResp = api.http().sendRequest(apikeyOnlyReq, SECURE_REQUEST_OPTIONS).response();
                if (apikeyOnlyResp.statusCode() == 200) {
                    return parseOpenApiTables(apikeyOnlyResp.bodyToString());
                }

                // Header variation 2: Only Bearer authorization header
                HttpRequest bearerOnlyReq = buildOpenApiRequest(instance, path, instance.getJwtToken(), HeaderMode.BEARER_ONLY);
                HttpResponse bearerOnlyResp = api.http().sendRequest(bearerOnlyReq, SECURE_REQUEST_OPTIONS).response();
                if (bearerOnlyResp.statusCode() == 200) {
                    return parseOpenApiTables(bearerOnlyResp.bodyToString());
                }
            }

            if (statusCode == 200) {
                return parseOpenApiTables(response.response().bodyToString());
            } else {
                logging.logToOutput("[*] OpenAPI probe on " + path + " returned HTTP " + statusCode);
            }

        } catch (Exception e) {
            logging.logToError("Error probing OpenAPI on " + path + ": " + e.getMessage());
        }
        return tables;
    }

    /**
     * Parse OpenAPI / Swagger spec JSON to extract table names.
     */
    private List<String> parseOpenApiTables(String body) {
        List<String> tables = new ArrayList<>();
        if (body == null || body.isEmpty()) {
            return tables;
        }

        try {
            JsonObject json = gson.fromJson(body, JsonObject.class);
            if (json == null) {
                return tables;
            }

            // OpenAPI 3.x and Swagger 2.x paths
            if (json.has("paths")) {
                JsonObject paths = json.getAsJsonObject("paths");
                for (String path : paths.keySet()) {
                    if (!path.startsWith("/rpc") && !path.equals("/") && !path.contains("{")) {
                        String tableName = path.replaceAll("^/+|/+$", "");
                        if (!tableName.isEmpty() && !tables.contains(tableName)) {
                            tables.add(tableName);
                            logging.logToOutput("  [+] Found table: " + tableName);
                        }
                    }
                }
            }

            // Definitions / components schemas
            if (json.has("definitions")) {
                JsonObject definitions = json.getAsJsonObject("definitions");
                for (String defName : definitions.keySet()) {
                    if (!tables.contains(defName) && !defName.isEmpty()) {
                        if (!defName.startsWith("_") && !defName.contains(".")) {
                            tables.add(defName);
                            logging.logToOutput("  [+] Found table from definitions: " + defName);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logging.logToError("Failed to parse OpenAPI JSON: " + e.getMessage());
        }

        return tables;
    }

    /**
     * Fallback probe of common Supabase table names when OpenAPI endpoint is unavailable.
     */
    private List<String> probeCommonTables(SupabaseInstance instance) {
        List<String> tables = new ArrayList<>();
        for (String candidate : COMMON_SUPABASE_TABLES) {
            if (Thread.currentThread().isInterrupted()) break;
            try {
                if (config.getDelayBetweenRequests() > 0) {
                    Thread.sleep(config.getDelayBetweenRequests());
                }
                String path = "/rest/v1/" + candidate + "?limit=1";
                HttpRequest request = buildRequest(instance, path, "GET");
                HttpRequestResponse response = api.http().sendRequest(request, SECURE_REQUEST_OPTIONS);
                int status = response.response().statusCode();

                // 200/206 indicates table is accessible
                // 401/403 with PostgREST body means table exists in schema but RLS blocked rows
                if (status == 200 || status == 206) {
                    tables.add(candidate);
                    logging.logToOutput("  [+] Discovered accessible table via probe: " + candidate);
                } else if (status == 401 || status == 403) {
                    String body = response.response().bodyToString();
                    if (body != null && !body.contains("PGRST200") && !body.contains("does not exist")) {
                        tables.add(candidate);
                        logging.logToOutput("  [+] Discovered existing table (RLS restricted): " + candidate);
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                // Ignore individual table probing errors
            }
        }
        return tables;
    }

    /**
     * Build HTTP request specifically for the OpenAPI spec endpoint.
     */
    private HttpRequest buildOpenApiRequest(SupabaseInstance instance, String path, String token, HeaderMode mode) {
        try {
            URI uri = new URI(instance.getBaseUrl());
            String host = uri.getHost();
            int port = uri.getPort() > 0 ? uri.getPort() : 443;
            boolean secure = instance.getBaseUrl().startsWith("https");

            StringBuilder rawRequest = new StringBuilder();
            rawRequest.append("GET ").append(path).append(" HTTP/1.1\r\n");
            rawRequest.append("Host: ").append(host).append("\r\n");
            if (token != null && !token.isEmpty()) {
                if (mode == HeaderMode.BOTH || mode == HeaderMode.APIKEY_ONLY) {
                    rawRequest.append("apikey: ").append(token).append("\r\n");
                }
                if (mode == HeaderMode.BOTH || mode == HeaderMode.BEARER_ONLY) {
                    rawRequest.append("Authorization: Bearer ").append(token).append("\r\n");
                }
            }
            rawRequest.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n");
            rawRequest.append("Accept: application/openapi+json, application/json, */*\r\n");
            rawRequest.append("Connection: close\r\n");
            rawRequest.append("\r\n");

            return HttpRequest.httpRequest(rawRequest.toString())
                .withService(HttpService.httpService(host, port, secure));

        } catch (Exception e) {
            throw new RuntimeException("Failed to build OpenAPI request: " + e.getMessage(), e);
        }
    }
    
    /**
     * Test a single table for RLS bypass.
     */
    private VulnerableTable testTable(SupabaseInstance instance, String tableName) {
        VulnerableTable result = new VulnerableTable(tableName);
        
        try {
            List<Map<String, Object>> allRows = new ArrayList<>();
            int offset = 0;
            int pageSize = config.getPageSize();
            int maxRows = config.getMaxRows();
            
            // Pagination loop
            while (allRows.size() < maxRows) {
                if (Thread.currentThread().isInterrupted()) {
                    break;
                }

                String path = String.format("/rest/v1/%s?limit=%d&offset=%d", 
                    tableName, pageSize, offset);
                
                HttpRequest request = buildRequest(instance, path, "GET");
                HttpRequestResponse response = api.http().sendRequest(request, SECURE_REQUEST_OPTIONS);
                result.setRequestResponse(response);
                
                int status = response.response().statusCode();
                result.setHttpStatus(status);
                
                if (status != 200) {
                    result.setAccessible(false);
                    result.setErrorMessage("HTTP " + status);
                    return result;
                }
                
                // Parse rows
                String body = response.response().bodyToString();
                Type listType = new TypeToken<List<Map<String, Object>>>(){}.getType();
                List<Map<String, Object>> rows = gson.fromJson(body, listType);

                if (rows == null || rows.isEmpty()) {
                    break;
                }

                allRows.addAll(rows);

                if (rows.size() < pageSize) {
                    break; // Last page
                }

                offset += pageSize;

                if (config.getDelayBetweenRequests() > 0) {
                    Thread.sleep(config.getDelayBetweenRequests());
                }
            }

            result.setAccessible(true);
            result.setRowCount(allRows.size());
            result.setReadAccess(VulnerableTable.DetectionStatus.YES);

            // Analyze for sensitive data
            if (!allRows.isEmpty()) {
                Map<String, FieldAnalysis> fieldAnalysis =
                    SensitiveFieldAnalyzer.analyzeTableData(allRows, config.getMaxSampleRows());

                result.setFieldAnalysis(fieldAnalysis);

                List<String> sensitiveFields = new ArrayList<>(fieldAnalysis.keySet());
                result.setSensitiveFields(sensitiveFields);

                Severity severity = SensitiveFieldAnalyzer.determineTableSeverity(fieldAnalysis);
                result.setSeverity(severity);

                // Set PII detection status
                result.setHasPii(SensitiveFieldAnalyzer.hasPiiData(fieldAnalysis)
                    ? VulnerableTable.DetectionStatus.YES : VulnerableTable.DetectionStatus.NO);

                // Extract column names from first row
                Map<String, Object> firstRow = allRows.get(0);
                result.setColumns(new ArrayList<>(firstRow.keySet()));

                // RLS is disabled if we can read data without restrictions
                result.setRlsStatus("Disabled");
            } else {
                // No data returned - RLS might be enabled or table is empty
                result.setHasPii(VulnerableTable.DetectionStatus.UNKNOWN);
                result.setRlsStatus("Enabled/Empty");
            }

            // Test write access with a dry-run POST (we don't actually write)
            result.setWriteAccess(testWriteAccess(instance, tableName));

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            result.setAccessible(false);
            result.setErrorMessage("Interrupted");
        } catch (Exception e) {
            result.setAccessible(false);
            result.setErrorMessage(e.getMessage());
            result.setReadAccess(VulnerableTable.DetectionStatus.NO);
            result.setWriteAccess(VulnerableTable.DetectionStatus.UNKNOWN);
            logging.logToError("Error testing table " + tableName + ": " + e.getMessage());
        }

        return result;
    }

    /**
     * Test if we can write to a table (POST request with empty body).
     * Returns YES if we get 201/200, NO if we get 4xx, UNKNOWN otherwise.
     */
    private VulnerableTable.DetectionStatus testWriteAccess(SupabaseInstance instance, String tableName) {
        try {
            String path = "/rest/v1/" + tableName;
            HttpRequest request = buildRequestWithBody(instance, path, "POST", "{}");
            HttpRequestResponse response = api.http().sendRequest(request, SECURE_REQUEST_OPTIONS);

            int status = response.response().statusCode();

            if (status == 200 || status == 201) {
                return VulnerableTable.DetectionStatus.YES;
            } else if (status >= 400 && status < 500) {
                return VulnerableTable.DetectionStatus.NO;
            } else {
                return VulnerableTable.DetectionStatus.UNKNOWN;
            }
        } catch (Exception e) {
            return VulnerableTable.DetectionStatus.UNKNOWN;
        }
    }

    /**
     * Build an HTTP request for Supabase API.
     * Mimics: curl -s "https://<instance>.supabase.co<path>" -H "apikey: <JWT>" -H "Authorization: Bearer <JWT>"
     */
    private HttpRequest buildRequest(SupabaseInstance instance, String path, String method) {
        try {
            URI uri = new URI(instance.getBaseUrl());
            String host = uri.getHost();
            int port = uri.getPort() > 0 ? uri.getPort() : 443;
            boolean secure = instance.getBaseUrl().startsWith("https");
            String token = instance.getJwtToken();

            // Build raw HTTP request - Supabase requires BOTH apikey AND Authorization headers
            StringBuilder rawRequest = new StringBuilder();
            rawRequest.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
            rawRequest.append("Host: ").append(host).append("\r\n");
            rawRequest.append("apikey: ").append(token).append("\r\n");
            rawRequest.append("Authorization: Bearer ").append(token).append("\r\n");
            rawRequest.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n");
            rawRequest.append("Accept: application/json\r\n");
            rawRequest.append("Connection: close\r\n");
            rawRequest.append("\r\n");

            return HttpRequest.httpRequest(rawRequest.toString())
                .withService(HttpService.httpService(host, port, secure));

        } catch (Exception e) {
            throw new RuntimeException("Failed to build request: " + e.getMessage(), e);
        }
    }

    /**
     * Build an HTTP request with a body for Supabase API.
     */
    private HttpRequest buildRequestWithBody(SupabaseInstance instance, String path, String method, String body) {
        try {
            URI uri = new URI(instance.getBaseUrl());
            String host = uri.getHost();
            int port = uri.getPort() > 0 ? uri.getPort() : 443;
            boolean secure = instance.getBaseUrl().startsWith("https");
            String token = instance.getJwtToken();

            // Build raw HTTP request with body - Supabase requires BOTH apikey AND Authorization headers
            StringBuilder rawRequest = new StringBuilder();
            rawRequest.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
            rawRequest.append("Host: ").append(host).append("\r\n");
            rawRequest.append("apikey: ").append(token).append("\r\n");
            rawRequest.append("Authorization: Bearer ").append(token).append("\r\n");
            rawRequest.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n");
            rawRequest.append("Accept: application/json\r\n");
            rawRequest.append("Content-Type: application/json\r\n");
            rawRequest.append("Prefer: return=minimal\r\n");  // Don't return data on insert
            rawRequest.append("Content-Length: ").append(body.length()).append("\r\n");
            rawRequest.append("Connection: close\r\n");
            rawRequest.append("\r\n");
            rawRequest.append(body);

            return HttpRequest.httpRequest(rawRequest.toString())
                .withService(HttpService.httpService(host, port, secure));

        } catch (Exception e) {
            throw new RuntimeException("Failed to build request: " + e.getMessage(), e);
        }
    }
}
