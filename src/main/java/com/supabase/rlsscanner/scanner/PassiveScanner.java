/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Passive scanner component
 */

package com.supabase.rlsscanner.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.logging.Logging;
import com.supabase.rlsscanner.core.InstanceStore;
import com.supabase.rlsscanner.core.ScannerConfig;

import java.util.function.Consumer;

/**
 * Legacy HTTP handler component.
 * Token and URL extraction logic has been moved to SupabaseScanCheck.passiveAudit(),
 * and active RLS probing has been moved to SupabaseScanCheck.activeAudit(),
 * per Montoya API best practices and PortSwigger requirements.
 */
public class PassiveScanner implements HttpHandler {

    private final MontoyaApi api;
    private final Logging logging;
    private final ScannerConfig config;
    private final InstanceStore instanceStore;
    private ActiveScanner activeScanner;
    private Consumer<String> statusListener;

    public PassiveScanner(MontoyaApi api, ScannerConfig config, InstanceStore instanceStore) {
        this.api = api;
        this.logging = api.logging();
        this.config = config;
        this.instanceStore = instanceStore;
    }

    /**
     * Set the active scanner.
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
     * Clear all cached passive scanner state.
     */
    public void clear() {
        logging.logToOutput("[*] Cleared passive scanner state");
    }
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Passive inspection and active probing are handled by Montoya scan checks
        // (SupabaseScanCheck via registerPassiveScanCheck and registerActiveScanCheck).
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }
    
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        // Passive inspection and active probing are handled by Montoya scan checks
        // (SupabaseScanCheck via registerPassiveScanCheck and registerActiveScanCheck).
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}
