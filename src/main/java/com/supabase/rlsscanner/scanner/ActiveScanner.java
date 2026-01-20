/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Active scanner for testing RLS policies
 */

package com.supabase.rlsscanner.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
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
     * Enumerate available tables using the OpenAPI endpoint.
     * Supabase exposes an OpenAPI spec at /rest/v1/ that lists all available tables.
     */
    private List<String> enumerateTables(SupabaseInstance instance) {
        List<String> tables = new ArrayList<>();

        try {
            // Build request specifically for OpenAPI spec endpoint
            HttpRequest request = buildOpenApiRequest(instance);

            logging.logToOutput("[*] Fetching OpenAPI spec from " + instance.getBaseUrl() + "/rest/v1/");
            HttpRequestResponse response = api.http().sendRequest(request);

            int statusCode = response.response().statusCode();
            if (statusCode != 200) {
                logging.logToError("Failed to enumerate tables: HTTP " + statusCode);
                String responseBody = response.response().bodyToString();
                if (responseBody != null && !responseBody.isEmpty()) {
                    logging.logToError("Response: " + responseBody.substring(0, Math.min(500, responseBody.length())));
                }
                return tables;
            }

            String body = response.response().bodyToString();
            logging.logToOutput("[*] Received OpenAPI spec (" + body.length() + " bytes)");

            // Parse OpenAPI spec
            JsonObject json = gson.fromJson(body, JsonObject.class);

            if (json == null) {
                logging.logToError("Failed to parse OpenAPI spec as JSON");
                return tables;
            }

            // OpenAPI 3.x uses "paths", Swagger 2.x also uses "paths"
            if (json.has("paths")) {
                JsonObject paths = json.getAsJsonObject("paths");
                for (String path : paths.keySet()) {
                    // Filter out RPC endpoints, root path, and paths with parameters
                    if (!path.startsWith("/rpc") && !path.equals("/") && !path.contains("{")) {
                        String tableName = path.replaceAll("^/+|/+$", "");
                        if (!tableName.isEmpty()) {
                            tables.add(tableName);
                            logging.logToOutput("  [+] Found table: " + tableName);
                        }
                    }
                }
            }

            // Also check for "definitions" which contains table schemas
            if (json.has("definitions")) {
                JsonObject definitions = json.getAsJsonObject("definitions");
                for (String defName : definitions.keySet()) {
                    // Skip if already found via paths
                    if (!tables.contains(defName) && !defName.isEmpty()) {
                        // Only add if it looks like a table (not a system definition)
                        if (!defName.startsWith("_") && !defName.contains(".")) {
                            tables.add(defName);
                            logging.logToOutput("  [+] Found table from definitions: " + defName);
                        }
                    }
                }
            }

        } catch (Exception e) {
            logging.logToError("Error enumerating tables: " + e.getMessage());
            e.printStackTrace();
        }

        logging.logToOutput("[*] Total tables found: " + tables.size());
        return tables;
    }

    /**
     * Build HTTP request specifically for the OpenAPI spec endpoint.
     * Mimics: curl -s "https://<instance>.supabase.co/rest/v1/" -H "apikey: <JWT>"
     */
    private HttpRequest buildOpenApiRequest(SupabaseInstance instance) {
        try {
            URI uri = new URI(instance.getBaseUrl());
            String host = uri.getHost();
            int port = uri.getPort() > 0 ? uri.getPort() : 443;
            boolean secure = instance.getBaseUrl().startsWith("https");
            String token = instance.getJwtToken();

            // Build raw HTTP request to match curl behavior exactly
            // Supabase requires BOTH apikey AND Authorization headers
            StringBuilder rawRequest = new StringBuilder();
            rawRequest.append("GET /rest/v1/ HTTP/1.1\r\n");
            rawRequest.append("Host: ").append(host).append("\r\n");
            rawRequest.append("apikey: ").append(token).append("\r\n");
            rawRequest.append("Authorization: Bearer ").append(token).append("\r\n");
            rawRequest.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n");
            rawRequest.append("Accept: */*\r\n");
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
                String path = String.format("/rest/v1/%s?limit=%d&offset=%d", 
                    tableName, pageSize, offset);
                
                HttpRequest request = buildRequest(instance, path, "GET");
                HttpRequestResponse response = api.http().sendRequest(request);
                
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
            HttpRequestResponse response = api.http().sendRequest(request);

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

