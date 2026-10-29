/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * 
 * A Burp Suite extension for detecting Supabase Row Level Security (RLS) 
 * misconfigurations and exposed JWT tokens.
 * 
 * Features:
 * - Passive scanning: Detects Supabase instances and JWT tokens in HTTP traffic
 * - Active testing: Tests discovered instances for RLS policy bypasses
 * - Sensitive data detection: Identifies exposed PII and sensitive fields
 * - Issue reporting: Integrates with Burp Scanner for findings
 * 
 * @author Supabase RLS Scanner Team
 * @version 1.0.0
 */

package com.supabase.rlsscanner;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.supabase.rlsscanner.core.InstanceStore;
import com.supabase.rlsscanner.core.ScannerConfig;
import com.supabase.rlsscanner.scanner.ActiveScanner;
import com.supabase.rlsscanner.scanner.PassiveScanner;
import com.supabase.rlsscanner.scanner.SupabaseScanCheck;
import com.supabase.rlsscanner.ui.ScannerPanel;

/**
 * Main extension class for Supabase RLS Security Scanner.
 * Implements BurpExtension for Montoya API integration.
 */
public class SupabaseRlsScanner implements BurpExtension {
    
    private static final String EXTENSION_NAME = "Supabase RLS Scanner";
    private static final String VERSION = "1.0.0";
    
    private MontoyaApi api;
    private Logging logging;
    private ScannerConfig config;
    private InstanceStore instanceStore;
    private PassiveScanner passiveScanner;
    private ActiveScanner activeScanner;
    private SupabaseScanCheck scanCheck;
    private ScannerPanel scannerPanel;
    
    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();
        
        // Set extension name
        api.extension().setName(EXTENSION_NAME);
        
        logging.logToOutput("========================================");
        logging.logToOutput(EXTENSION_NAME + " v" + VERSION);
        logging.logToOutput("========================================");
        logging.logToOutput("Initializing extension...");
        
        try {
            // Initialize core components
            initializeCoreComponents();
            
            // Register passive scanner check using modern Montoya API
            api.scanner().registerPassiveScanCheck(scanCheck, ScanCheckType.PER_REQUEST);
            logging.logToOutput("[+] Registered passive scanner check");

            // Register active scanner check using modern Montoya API
            api.scanner().registerActiveScanCheck(scanCheck, ScanCheckType.PER_REQUEST);
            logging.logToOutput("[+] Registered active scanner check");
            
            // Register UI tab
            api.userInterface().registerSuiteTab(EXTENSION_NAME, scannerPanel);
            logging.logToOutput("[+] Registered UI tab");
            
            // Register unload handler
            api.extension().registerUnloadingHandler(new UnloadHandler());
            
            logging.logToOutput("");
            logging.logToOutput("[*] Extension loaded successfully!");
            logging.logToOutput("[*] Passive scanning: " +
                (config.isPassiveScanningEnabled() ? "ENABLED" : "DISABLED"));
            logging.logToOutput("[*] Active testing: " +
                (config.isActiveTestingEnabled() ? "ENABLED" : "DISABLED"));
            logging.logToOutput("[*] Auto-enumerate: " +
                (config.isAutoEnumerateEnabled() ? "ENABLED" : "DISABLED"));
            logging.logToOutput("[*] Browse the target application to discover Supabase instances.");
            logging.logToOutput("");
            logging.logToOutput("========================================");
            logging.logToOutput("!! IMPORTANT NOTICE !!");
            logging.logToOutput("========================================");
            logging.logToOutput("This tool provides basic security checks only - not suitable");
            logging.logToOutput("for production applications.");
            logging.logToOutput("");
            logging.logToOutput("For comprehensive application security audits, compliance reviews,");
            logging.logToOutput("audit readiness assessments, threat modeling, and production");
            logging.logToOutput("readiness validation, reach out to Securify AI for one");
            logging.logToOutput("complimentary consultation at: contact@securifyai.co");
            logging.logToOutput("========================================");
            logging.logToOutput("");
            
        } catch (Exception e) {
            logging.logToError("Failed to initialize extension: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Initialize all core components.
     */
    private void initializeCoreComponents() {
        // Configuration
        config = new ScannerConfig(api);
        logging.logToOutput("[+] Loaded configuration");
        
        // Instance store
        instanceStore = new InstanceStore();
        logging.logToOutput("[+] Initialized instance store");
        
        // Active scanner
        activeScanner = new ActiveScanner(api, config);
        logging.logToOutput("[+] Initialized active scanner");

        // Burp scanner check (passive & active)
        scanCheck = new SupabaseScanCheck(api, config, instanceStore, activeScanner);
        logging.logToOutput("[+] Initialized scanner check");

        // Passive scanner (kept for compatibility)
        passiveScanner = new PassiveScanner(api, config, instanceStore);
        passiveScanner.setActiveScanner(activeScanner);

        // UI Panel
        scannerPanel = new ScannerPanel(api, config, instanceStore, activeScanner, scanCheck, passiveScanner);
        logging.logToOutput("[+] Initialized UI panel");

        // Wire up scan check status listener to UI panel
        scanCheck.setStatusListener(scannerPanel::logStatus);
    }
    
    /**
     * Handler for extension unload.
     */
    private class UnloadHandler implements ExtensionUnloadingHandler {
        @Override
        public void extensionUnloaded() {
            logging.logToOutput("Unloading " + EXTENSION_NAME + "...");
            
            // Cleanup
            if (scannerPanel != null) {
                scannerPanel.shutdown();
            }
            
            if (config != null) {
                config.saveSettings();
            }
            
            logging.logToOutput("Extension unloaded successfully.");
        }
    }
}
