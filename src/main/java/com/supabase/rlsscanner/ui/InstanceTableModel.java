/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Table model for discovered instances
 */

package com.supabase.rlsscanner.ui;

import com.supabase.rlsscanner.models.SupabaseInstance;

import javax.swing.table.AbstractTableModel;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying discovered Supabase instances.
 * Shows all instances with valid credentials.
 */
public class InstanceTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "Base URL", "Role", "JWT Token", "Source", "Severity", "Tables", "Tested", "Discovered"
    };

    private static final DateTimeFormatter TIME_FORMAT =
        DateTimeFormatter.ofPattern("HH:mm:ss");

    // All instances (including hidden ones)
    private final List<SupabaseInstance> allInstances;

    // Filtered instances for display
    private final List<SupabaseInstance> displayedInstances;

    public InstanceTableModel() {
        this.allInstances = new ArrayList<>();
        this.displayedInstances = new ArrayList<>();
    }

    /**
     * Check if an instance should be displayed.
     * Show all instances with valid credentials (have JWT token).
     */
    private boolean shouldDisplay(SupabaseInstance instance) {
        // Show any instance that has valid credentials (has a JWT token)
        return instance.hasValidCredentials();
    }

    /**
     * Rebuild the displayed instances list based on filter criteria.
     */
    private void rebuildDisplayedList() {
        displayedInstances.clear();
        for (SupabaseInstance instance : allInstances) {
            if (shouldDisplay(instance)) {
                displayedInstances.add(instance);
            }
        }
    }

    @Override
    public int getRowCount() {
        return displayedInstances.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (rowIndex < 0 || rowIndex >= displayedInstances.size()) {
            return "";
        }

        SupabaseInstance instance = displayedInstances.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> instance.getBaseUrl();
            case 1 -> formatRole(instance);
            case 2 -> formatTokens(instance);
            case 3 -> instance.getSourceUrl() != null ? instance.getSourceUrl() : "";
            case 4 -> instance.getOverallSeverity().getDisplayName();
            case 5 -> String.valueOf(instance.getTables().size());
            case 6 -> instance.isTested() ? "Yes" : "No";
            case 7 -> instance.getDiscoveredAt() != null
                ? TIME_FORMAT.format(instance.getDiscoveredAt()) : "";
            default -> "";
        };
    }

    /**
     * Format role display - flag service_role as critical.
     */
    private String formatRole(SupabaseInstance instance) {
        String role = instance.getJwtRole();
        if (role == null) return "-";

        // Show both roles if both tokens are present
        if (instance.hasAnonToken() && instance.hasServiceRoleToken()) {
            return "anon + SERVICE_ROLE [CRITICAL]";
        } else if (instance.hasServiceRoleToken()) {
            return "SERVICE_ROLE [CRITICAL]";
        } else if (instance.hasAnonToken()) {
            return "anon";
        }

        return role;
    }

    /**
     * Format tokens for display - show both if available.
     */
    private String formatTokens(SupabaseInstance instance) {
        if (instance.hasAnonToken() && instance.hasServiceRoleToken()) {
            return "[anon + service_role tokens]";
        } else if (instance.hasServiceRoleToken()) {
            return instance.getServiceRoleToken();
        } else if (instance.hasAnonToken()) {
            return instance.getAnonToken();
        }
        return "";
    }
    
    /**
     * Add a new instance to the model.
     */
    public synchronized void addInstance(SupabaseInstance instance) {
        // Check if already exists in allInstances
        for (int i = 0; i < allInstances.size(); i++) {
            if (allInstances.get(i).getBaseUrl().equals(instance.getBaseUrl())) {
                allInstances.set(i, instance);
                rebuildDisplayedList();
                fireTableDataChanged();
                return;
            }
        }

        // Add to all instances
        allInstances.add(instance);

        // Only add to display if it passes the filter
        if (shouldDisplay(instance)) {
            displayedInstances.add(instance);
            int index = displayedInstances.size() - 1;
            fireTableRowsInserted(index, index);
        }
    }

    /**
     * Update an existing instance.
     */
    public synchronized void updateInstance(SupabaseInstance instance) {
        for (int i = 0; i < allInstances.size(); i++) {
            if (allInstances.get(i).getBaseUrl().equals(instance.getBaseUrl())) {
                allInstances.set(i, instance);
                // Rebuild displayed list since filter criteria might have changed
                rebuildDisplayedList();
                fireTableDataChanged();
                return;
            }
        }
    }

    /**
     * Get instance at row (from displayed instances).
     */
    public synchronized SupabaseInstance getInstanceAt(int rowIndex) {
        if (rowIndex < 0 || rowIndex >= displayedInstances.size()) {
            return null;
        }
        return displayedInstances.get(rowIndex);
    }

    /**
     * Get all displayed instances (for export, etc.).
     */
    public synchronized List<SupabaseInstance> getAllInstances() {
        return new ArrayList<>(displayedInstances);
    }

    /**
     * Get all instances including hidden ones.
     */
    public synchronized List<SupabaseInstance> getAllInstancesIncludingHidden() {
        return new ArrayList<>(allInstances);
    }

    /**
     * Clear all instances.
     */
    public synchronized void clear() {
        int size = displayedInstances.size();
        allInstances.clear();
        displayedInstances.clear();
        if (size > 0) {
            fireTableRowsDeleted(0, size - 1);
        }
    }

    /**
     * Refresh the entire table.
     */
    public void refresh() {
        rebuildDisplayedList();
        fireTableDataChanged();
    }
}

