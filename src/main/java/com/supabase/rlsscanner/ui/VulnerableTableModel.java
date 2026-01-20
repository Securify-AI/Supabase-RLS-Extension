/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Table model for vulnerable tables
 */

package com.supabase.rlsscanner.ui;

import com.supabase.rlsscanner.models.Severity;
import com.supabase.rlsscanner.models.VulnerableTable;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying vulnerable tables with RLS issues.
 */
public class VulnerableTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {
        "Table", "Severity", "RLS", "Read", "Write", "Rows", "PII", "Columns"
    };

    private final List<VulnerableTable> tables;

    public VulnerableTableModel() {
        this.tables = new ArrayList<>();
    }

    @Override
    public int getRowCount() {
        return tables.size();
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
        if (rowIndex < 0 || rowIndex >= tables.size()) {
            return "";
        }

        VulnerableTable table = tables.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> table.getTableName();
            case 1 -> table.getSeverity().getDisplayName();
            case 2 -> table.getRlsStatus();
            case 3 -> table.getReadAccess().getDisplay();
            case 4 -> table.getWriteAccess().getDisplay();
            case 5 -> String.valueOf(table.getRowCount());
            case 6 -> table.getHasPii().getDisplay();
            case 7 -> table.getColumnsDisplay();
            default -> "";
        };
    }

    /**
     * Get the severity for a row (used by the cell renderer).
     */
    public Severity getSeverityAt(int rowIndex) {
        if (rowIndex < 0 || rowIndex >= tables.size()) {
            return Severity.NONE;
        }
        return tables.get(rowIndex).getSeverity();
    }

    /**
     * Set tables for an instance.
     */
    public synchronized void setTables(List<VulnerableTable> newTables) {
        tables.clear();
        if (newTables != null) {
            tables.addAll(newTables);
        }
        fireTableDataChanged();
    }

    /**
     * Get table at row.
     */
    public synchronized VulnerableTable getTableAt(int rowIndex) {
        if (rowIndex < 0 || rowIndex >= tables.size()) {
            return null;
        }
        return tables.get(rowIndex);
    }

    /**
     * Clear all tables.
     */
    public synchronized void clear() {
        int size = tables.size();
        if (size > 0) {
            tables.clear();
            fireTableRowsDeleted(0, size - 1);
        }
    }

    /**
     * Custom cell renderer for color-coded severity column.
     */
    public static class SeverityCellRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {

            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

            if (!isSelected && table.getModel() instanceof VulnerableTableModel model) {
                Severity severity = model.getSeverityAt(row);
                c.setBackground(getSeverityColor(severity));
                c.setForeground(Color.BLACK);
            }

            return c;
        }

        private Color getSeverityColor(Severity severity) {
            return switch (severity) {
                case CRITICAL -> new Color(255, 102, 102);  // Light red
                case HIGH -> new Color(255, 178, 102);      // Light orange
                case MEDIUM -> new Color(255, 255, 102);    // Light yellow
                case LOW -> new Color(178, 255, 102);       // Light green
                case INFO -> new Color(178, 218, 255);      // Light blue
                case NONE -> Color.WHITE;
            };
        }
    }
}

