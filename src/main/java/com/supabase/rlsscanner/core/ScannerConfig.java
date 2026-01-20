/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Scanner configuration
 */

package com.supabase.rlsscanner.core;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

/**
 * Configuration manager for the Supabase RLS Scanner.
 * Uses Burp's persistence API to save settings.
 */
public class ScannerConfig {
    
    // Configuration keys
    private static final String KEY_PASSIVE_SCANNING_ENABLED = "passiveScanningEnabled";
    private static final String KEY_ACTIVE_TESTING_ENABLED = "activeTestingEnabled";
    private static final String KEY_AUTO_ENUMERATE_ENABLED = "autoEnumerateEnabled";
    private static final String KEY_PAGE_SIZE = "pageSize";
    private static final String KEY_MAX_ROWS = "maxRows";
    private static final String KEY_REQUEST_TIMEOUT = "requestTimeout";
    private static final String KEY_DELAY_BETWEEN_REQUESTS = "delayBetweenRequests";
    private static final String KEY_MAX_SAMPLE_ROWS = "maxSampleRows";
    private static final String KEY_SOUND_ALERTS_ENABLED = "soundAlertsEnabled";

    // Default values
    private static final boolean DEFAULT_PASSIVE_SCANNING = true;
    private static final boolean DEFAULT_ACTIVE_TESTING = false;
    private static final boolean DEFAULT_AUTO_ENUMERATE = false;
    private static final int DEFAULT_PAGE_SIZE = 1000;
    private static final int DEFAULT_MAX_ROWS = 10000;
    private static final int DEFAULT_REQUEST_TIMEOUT = 10;
    private static final int DEFAULT_DELAY_BETWEEN_REQUESTS = 100;
    private static final int DEFAULT_MAX_SAMPLE_ROWS = 100;
    private static final boolean DEFAULT_SOUND_ALERTS = true;

    private final PersistedObject persistence;

    // Current settings
    private boolean passiveScanningEnabled;
    private boolean activeTestingEnabled;
    private boolean autoEnumerateEnabled;
    private int pageSize;
    private int maxRows;
    private int requestTimeout;
    private int delayBetweenRequests;
    private int maxSampleRows;
    private boolean soundAlertsEnabled;
    
    public ScannerConfig(MontoyaApi api) {
        this.persistence = api.persistence().extensionData();
        loadSettings();
    }
    
    /**
     * Load settings from Burp persistence.
     */
    private void loadSettings() {
        passiveScanningEnabled = persistence.getBoolean(KEY_PASSIVE_SCANNING_ENABLED) != null
            ? persistence.getBoolean(KEY_PASSIVE_SCANNING_ENABLED) : DEFAULT_PASSIVE_SCANNING;
        activeTestingEnabled = persistence.getBoolean(KEY_ACTIVE_TESTING_ENABLED) != null
            ? persistence.getBoolean(KEY_ACTIVE_TESTING_ENABLED) : DEFAULT_ACTIVE_TESTING;
        autoEnumerateEnabled = persistence.getBoolean(KEY_AUTO_ENUMERATE_ENABLED) != null
            ? persistence.getBoolean(KEY_AUTO_ENUMERATE_ENABLED) : DEFAULT_AUTO_ENUMERATE;
        pageSize = persistence.getInteger(KEY_PAGE_SIZE) != null
            ? persistence.getInteger(KEY_PAGE_SIZE) : DEFAULT_PAGE_SIZE;
        maxRows = persistence.getInteger(KEY_MAX_ROWS) != null
            ? persistence.getInteger(KEY_MAX_ROWS) : DEFAULT_MAX_ROWS;
        requestTimeout = persistence.getInteger(KEY_REQUEST_TIMEOUT) != null
            ? persistence.getInteger(KEY_REQUEST_TIMEOUT) : DEFAULT_REQUEST_TIMEOUT;
        delayBetweenRequests = persistence.getInteger(KEY_DELAY_BETWEEN_REQUESTS) != null
            ? persistence.getInteger(KEY_DELAY_BETWEEN_REQUESTS) : DEFAULT_DELAY_BETWEEN_REQUESTS;
        maxSampleRows = persistence.getInteger(KEY_MAX_SAMPLE_ROWS) != null
            ? persistence.getInteger(KEY_MAX_SAMPLE_ROWS) : DEFAULT_MAX_SAMPLE_ROWS;
        soundAlertsEnabled = persistence.getBoolean(KEY_SOUND_ALERTS_ENABLED) != null
            ? persistence.getBoolean(KEY_SOUND_ALERTS_ENABLED) : DEFAULT_SOUND_ALERTS;
    }
    
    /**
     * Save all settings to Burp persistence.
     */
    public void saveSettings() {
        persistence.setBoolean(KEY_PASSIVE_SCANNING_ENABLED, passiveScanningEnabled);
        persistence.setBoolean(KEY_ACTIVE_TESTING_ENABLED, activeTestingEnabled);
        persistence.setBoolean(KEY_AUTO_ENUMERATE_ENABLED, autoEnumerateEnabled);
        persistence.setInteger(KEY_PAGE_SIZE, pageSize);
        persistence.setInteger(KEY_MAX_ROWS, maxRows);
        persistence.setInteger(KEY_REQUEST_TIMEOUT, requestTimeout);
        persistence.setInteger(KEY_DELAY_BETWEEN_REQUESTS, delayBetweenRequests);
        persistence.setInteger(KEY_MAX_SAMPLE_ROWS, maxSampleRows);
        persistence.setBoolean(KEY_SOUND_ALERTS_ENABLED, soundAlertsEnabled);
    }

    // Getters
    public boolean isPassiveScanningEnabled() { return passiveScanningEnabled; }
    public boolean isActiveTestingEnabled() { return activeTestingEnabled; }
    public boolean isAutoEnumerateEnabled() { return autoEnumerateEnabled; }
    public int getPageSize() { return pageSize; }
    public int getMaxRows() { return maxRows; }
    public int getRequestTimeout() { return requestTimeout; }
    public int getDelayBetweenRequests() { return delayBetweenRequests; }
    public int getMaxSampleRows() { return maxSampleRows; }
    public boolean isSoundAlertsEnabled() { return soundAlertsEnabled; }

    // Setters with auto-save
    public void setPassiveScanningEnabled(boolean enabled) {
        this.passiveScanningEnabled = enabled;
        persistence.setBoolean(KEY_PASSIVE_SCANNING_ENABLED, enabled);
    }

    public void setActiveTestingEnabled(boolean enabled) {
        this.activeTestingEnabled = enabled;
        persistence.setBoolean(KEY_ACTIVE_TESTING_ENABLED, enabled);
    }

    public void setAutoEnumerateEnabled(boolean enabled) {
        this.autoEnumerateEnabled = enabled;
        persistence.setBoolean(KEY_AUTO_ENUMERATE_ENABLED, enabled);
    }
    
    public void setPageSize(int pageSize) {
        this.pageSize = pageSize;
        persistence.setInteger(KEY_PAGE_SIZE, pageSize);
    }
    
    public void setMaxRows(int maxRows) {
        this.maxRows = maxRows;
        persistence.setInteger(KEY_MAX_ROWS, maxRows);
    }
    
    public void setRequestTimeout(int timeout) {
        this.requestTimeout = timeout;
        persistence.setInteger(KEY_REQUEST_TIMEOUT, timeout);
    }
    
    public void setDelayBetweenRequests(int delay) {
        this.delayBetweenRequests = delay;
        persistence.setInteger(KEY_DELAY_BETWEEN_REQUESTS, delay);
    }
    
    public void setMaxSampleRows(int maxSampleRows) {
        this.maxSampleRows = maxSampleRows;
        persistence.setInteger(KEY_MAX_SAMPLE_ROWS, maxSampleRows);
    }
    
    public void setSoundAlertsEnabled(boolean enabled) {
        this.soundAlertsEnabled = enabled;
        persistence.setBoolean(KEY_SOUND_ALERTS_ENABLED, enabled);
    }
    
    /**
     * Reset all settings to defaults.
     */
    public void resetToDefaults() {
        passiveScanningEnabled = DEFAULT_PASSIVE_SCANNING;
        activeTestingEnabled = DEFAULT_ACTIVE_TESTING;
        autoEnumerateEnabled = DEFAULT_AUTO_ENUMERATE;
        pageSize = DEFAULT_PAGE_SIZE;
        maxRows = DEFAULT_MAX_ROWS;
        requestTimeout = DEFAULT_REQUEST_TIMEOUT;
        delayBetweenRequests = DEFAULT_DELAY_BETWEEN_REQUESTS;
        maxSampleRows = DEFAULT_MAX_SAMPLE_ROWS;
        soundAlertsEnabled = DEFAULT_SOUND_ALERTS;
        saveSettings();
    }
}

