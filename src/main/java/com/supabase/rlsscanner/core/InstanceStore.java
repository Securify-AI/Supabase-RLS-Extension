/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Store for discovered Supabase instances
 */

package com.supabase.rlsscanner.core;

import com.supabase.rlsscanner.models.SupabaseInstance;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Thread-safe store for managing discovered Supabase instances.
 */
public class InstanceStore {
    
    // Map of baseUrl -> SupabaseInstance
    private final Map<String, SupabaseInstance> instances;
    
    // Set of discovered JWT tokens (for deduplication)
    private final Set<String> discoveredJwts;
    
    // Listeners for new instance discoveries
    private final List<Consumer<SupabaseInstance>> newInstanceListeners;
    
    // Listeners for instance updates
    private final List<Consumer<SupabaseInstance>> instanceUpdateListeners;
    
    public InstanceStore() {
        this.instances = new ConcurrentHashMap<>();
        this.discoveredJwts = Collections.newSetFromMap(new ConcurrentHashMap<>());
        this.newInstanceListeners = new ArrayList<>();
        this.instanceUpdateListeners = new ArrayList<>();
    }
    
    /**
     * Add or update a Supabase instance.
     * @param baseUrl The base URL of the Supabase instance
     * @param jwtToken The JWT token (can be null for updates)
     * @param sourceUrl The URL where this was discovered
     * @param context Additional context about the discovery
     * @return The instance (new or existing)
     */
    public synchronized SupabaseInstance addOrUpdate(
            String baseUrl, String jwtToken, String sourceUrl, String context) {

        if (baseUrl == null || baseUrl.isEmpty()) {
            return null;
        }

        String normalizedUrl = normalizeUrl(baseUrl);
        SupabaseInstance instance = instances.get(normalizedUrl);

        boolean isNew = (instance == null);

        if (isNew) {
            instance = new SupabaseInstance(normalizedUrl);
            instance.setSourceUrl(sourceUrl);
            instance.setDiscoveryContext(context);
            instances.put(normalizedUrl, instance);
        }

        // Update JWT if we have a new/better one
        if (jwtToken != null && !jwtToken.isEmpty()) {
            if (!discoveredJwts.contains(jwtToken)) {
                discoveredJwts.add(jwtToken);
                // Determine role and set appropriate token
                String role = com.supabase.rlsscanner.utils.PatternMatcher.extractRoleFromJwt(jwtToken);
                if ("anon".equals(role)) {
                    instance.setAnonToken(jwtToken);
                } else if ("service_role".equals(role)) {
                    instance.setServiceRoleToken(jwtToken);
                }
            }
        }

        // Notify listeners
        if (isNew) {
            notifyNewInstance(instance);
        } else {
            notifyInstanceUpdate(instance);
        }

        return instance;
    }
    
    /**
     * Get an instance by base URL.
     */
    public SupabaseInstance get(String baseUrl) {
        if (baseUrl == null) return null;
        return instances.get(normalizeUrl(baseUrl));
    }
    
    /**
     * Get all instances.
     */
    public List<SupabaseInstance> getAll() {
        return new ArrayList<>(instances.values());
    }
    
    /**
     * Get all instances that have valid credentials and are ready for testing.
     */
    public List<SupabaseInstance> getTestableInstances() {
        List<SupabaseInstance> testable = new ArrayList<>();
        for (SupabaseInstance instance : instances.values()) {
            if (instance.hasValidCredentials() && !instance.isTested()) {
                testable.add(instance);
            }
        }
        return testable;
    }
    
    /**
     * Get count of discovered instances.
     */
    public int getCount() {
        return instances.size();
    }
    
    /**
     * Check if we've seen a specific JWT token.
     */
    public boolean hasSeenJwt(String jwt) {
        return discoveredJwts.contains(jwt);
    }
    
    /**
     * Add a listener for new instance discoveries.
     */
    public void addNewInstanceListener(Consumer<SupabaseInstance> listener) {
        newInstanceListeners.add(listener);
    }
    
    /**
     * Add a listener for instance updates.
     */
    public void addInstanceUpdateListener(Consumer<SupabaseInstance> listener) {
        instanceUpdateListeners.add(listener);
    }
    
    /**
     * Clear all instances.
     */
    public void clear() {
        instances.clear();
        discoveredJwts.clear();
    }
    
    private void notifyNewInstance(SupabaseInstance instance) {
        for (Consumer<SupabaseInstance> listener : newInstanceListeners) {
            try {
                listener.accept(instance);
            } catch (Exception e) {
                // Log and continue
            }
        }
    }
    
    private void notifyInstanceUpdate(SupabaseInstance instance) {
        for (Consumer<SupabaseInstance> listener : instanceUpdateListeners) {
            try {
                listener.accept(instance);
            } catch (Exception e) {
                // Log and continue
            }
        }
    }
    
    private static String normalizeUrl(String url) {
        if (url == null) return null;
        return url.replaceAll("/+$", "").toLowerCase();
    }
}

