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
            
            // Register HTTP handler for passive scanning
            api.http().registerHttpHandler(passiveScanner);
            logging.logToOutput("[+] Registered passive scanner");
            
            // Register scanner check
            api.scanner().registerScanCheck(scanCheck);
            logging.logToOutput("[+] Registered scanner check");
            
            // Register UI tab
            api.userInterface().registerSuiteTab(EXTENSION_NAME, scannerPanel);
            logging.logToOutput("[+] Registered UI tab");
            
            // Register unload handler
            api.extension().registerUnloadingHandler(new UnloadHandler());
            
            logging.logToOutput("");
            logging.logToOutput("[*] Extension loaded successfully!");
            logging.logToOutput("[*] Passive scanning: " +
                (config.isPassiveScanningEnabled() ? "ENABLED" : "DISABLED"));
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

        // Passive scanner
        passiveScanner = new PassiveScanner(api, config, instanceStore);
        passiveScanner.setActiveScanner(activeScanner);  // Wire up for auto-enumeration
        logging.logToOutput("[+] Initialized passive scanner");

        // Burp scanner check
        scanCheck = new SupabaseScanCheck(api, config, instanceStore, activeScanner);
        logging.logToOutput("[+] Initialized scanner check");

        // UI Panel
        scannerPanel = new ScannerPanel(api, config, instanceStore, activeScanner, passiveScanner);
        logging.logToOutput("[+] Initialized UI panel");

        // Wire up PassiveScanner status listener to UI panel
        passiveScanner.setStatusListener(scannerPanel::logStatus);
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

