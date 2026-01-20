# Supabase RLS Security Scanner

A Burp Suite extension for detecting Supabase Row Level Security (RLS) misconfigurations and exposed JWT tokens in web applications.

## Overview

This extension provides automated security testing capabilities for Supabase-powered applications. It detects exposed Supabase credentials in HTTP traffic and tests for Row Level Security (RLS) policy bypasses that could lead to unauthorized data access.

### Key Capabilities

- **Automatic Discovery**: Passively identifies Supabase instances and JWT tokens in HTTP traffic
- **RLS Bypass Testing**: Actively tests database tables for Row Level Security misconfigurations
- **Sensitive Data Detection**: Identifies exposed PII, credentials, and financial data
- **Burp Integration**: Full integration with Burp Scanner for professional reporting

## Features

### Passive Scanning

The extension monitors HTTP traffic and automatically detects:

| Detection Type | Description |
|---------------|-------------|
| **JWT Tokens** | Supabase `anon` and `service_role` JWT tokens in responses |
| **Supabase URLs** | Standard `.supabase.co` cloud URLs |
| **Environment Variables** | NEXT_PUBLIC_SUPABASE_URL, VITE_SUPABASE_URL, REACT_APP_SUPABASE_URL patterns |
| **JSON Configurations** | Supabase configuration objects in JavaScript/JSON responses |
| **Critical Alerts** | Immediate notification when `service_role` tokens are exposed |

### Active Testing (RLS Bypass Detection)

When triggered manually via "Test RLS" button:

| Test Type | Description |
|-----------|-------------|
| **Table Enumeration** | Discovers all accessible tables via PostgREST API introspection |
| **Read Access Testing** | Tests each table for unauthorized SELECT access |
| **Write Access Testing** | Dry-run POST requests to detect INSERT permissions |
| **Row Count Analysis** | Reports number of accessible rows per table |
| **Column Discovery** | Identifies column names and data types |

### Sensitive Data Detection

The scanner classifies sensitive fields into severity categories:

| Severity | Field Patterns | Description |
|----------|---------------|-------------|
| **CRITICAL** | password, secret, api_key, private_key, token, jwt, credit_card, cvv, ssn | Credentials, secrets, and financial data |
| **HIGH** | email, phone, bank_account, salary, auth, session_id, user_id, medical_record | PII and authentication data |
| **MEDIUM** | address, ip_address, birth_date, device_id, location, coordinates | Location and device tracking data |

Value-based detection also identifies:
- JWT tokens embedded in field values
- Credit card number patterns (4-group 16-digit format)
- Email addresses in email-named fields
- Phone numbers in phone-named fields

### Issue Reporting

Findings integrate with Burp Scanner:

- **Severity Levels**: Critical, High, Medium, Low, Information
- **Confidence Ratings**: Certain, Firm, Tentative
- **Issue Details**: Vulnerability description, remediation guidance, background information
- **Evidence**: Marked HTTP request/response highlighting vulnerable data

## Installation

### Prerequisites

- Burp Suite Professional or Community Edition (2023.x or later)
- Java 17 or higher (required for Montoya API)

### Building from Source

**Linux/macOS (using Make):**
```bash
cd supabase-rls-scanner
make build
```

**Windows (using batch script):**
```cmd
cd supabase-rls-scanner
build.bat build
```

**All platforms (using Gradle):**
```bash
./gradlew clean build
```

The compiled JAR is output to: `build/libs/supabase-rls-scanner-1.0.0.jar`

### Loading in Burp Suite

1. Open Burp Suite
2. Navigate to **Extensions** → **Installed**
3. Click **Add**
4. Set Extension Type to **Java**
5. Select `supabase-rls-scanner-1.0.0.jar`
6. Click **Next** to load

The extension registers a new tab called "Supabase RLS Scanner".

## Usage Guide

### Passive Discovery Workflow

1. **Enable Passive Scanning**: Verify the checkbox is enabled in the Configuration panel
2. **Proxy Traffic**: Browse the target application through Burp Proxy
3. **Automatic Detection**: The extension monitors all HTTP responses for Supabase artifacts
4. **Instance Table**: Discovered instances appear in the "Discovered Supabase Instances" table
5. **Critical Alerts**: `service_role` token exposure triggers immediate logging

### Active Testing Workflow

1. **Select Instance**: Click on a discovered instance in the table
2. **Initiate Scan**: Click the "Test RLS" button
3. **Authorization Confirmation**: Confirm you have permission to test
4. **Scan Execution**: The scanner enumerates tables and tests access
5. **Review Results**: Vulnerable tables appear in the bottom panel with:
   - Table name and row count
   - Severity classification
   - Read/Write access status
   - PII detection status
   - Column names

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| **Passive Scanning** | Monitor HTTP traffic for Supabase artifacts | Enabled |
| **Active Testing** | Allow integration with Burp Scanner active checks | Enabled |
| **Auto-Enumerate** | Automatically scan new instances when discovered | Disabled |

### Export Functionality

- Click **Export** to save findings as JSON
- Includes all discovered instances, tables, and field analysis
- Format suitable for reporting and documentation

### Copy as cURL

Right-click on a vulnerable table to:
- **Copy as curl**: Generate a GET request to read table data
- **Copy as curl (POST/Write test)**: Generate a POST request to test write access

## Security Considerations

⚠️ **Responsible Use Guidelines**

| Consideration | Description |
|--------------|-------------|
| **Authorization** | Only test applications you own or have explicit permission to scan |
| **Active Testing** | Sends HTTP requests to target database - may trigger alerts |
| **Data Handling** | Exposed data may contain real PII - handle according to policy |
| **Credential Storage** | JWT tokens are held in memory only during session |
| **No Data Modification** | Write tests use empty payloads and minimal operations |

## Project Structure

```
supabase-rls-scanner/
├── src/main/java/com/supabase/rlsscanner/
│   ├── SupabaseRlsScanner.java      # Main extension entry point
│   ├── core/
│   │   ├── AlertManager.java         # Sound alerts for findings
│   │   ├── InstanceStore.java        # Supabase instance storage
│   │   └── ScannerConfig.java        # Configuration management
│   ├── models/
│   │   ├── FieldAnalysis.java        # Sensitive field analysis result
│   │   ├── ScanResult.java           # Full scan result container
│   │   ├── Severity.java             # Severity enumeration
│   │   ├── SupabaseInstance.java     # Supabase instance model
│   │   └── VulnerableTable.java      # Table vulnerability data
│   ├── scanner/
│   │   ├── ActiveScanner.java        # RLS bypass testing logic
│   │   ├── PassiveScanner.java       # HTTP traffic monitoring
│   │   └── SupabaseScanCheck.java    # Burp Scanner integration
│   ├── ui/
│   │   ├── InstanceTableModel.java   # Instance table UI model
│   │   ├── ScannerPanel.java         # Main UI panel
│   │   └── VulnerableTableModel.java # Vulnerable table UI model
│   └── utils/
│       ├── PatternMatcher.java       # Regex patterns for detection
│       ├── ReportExporter.java       # JSON export functionality
│       └── SensitiveFieldAnalyzer.java # Field sensitivity analysis
├── build.gradle                       # Gradle build configuration
├── Makefile                           # Unix build commands
└── build.bat                          # Windows build script
```

## License

MIT License - See LICENSE file for details.

