# Technical Documentation

## Architecture Overview

The Supabase RLS Scanner is a Burp Suite extension built using the Montoya API (Burp's modern Java API). It implements passive HTTP traffic analysis and active security testing for Supabase-powered applications.

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Burp Suite                                   │
├─────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  HTTP Proxy  │───▶│PassiveScanner│───▶│   InstanceStore      │  │
│  └──────────────┘    └──────────────┘    │  (JWT + URL storage) │  │
│                                          └──────────────────────┘  │
│  ┌──────────────┐    ┌──────────────┐              │               │
│  │Burp Scanner  │───▶│SupabaseScan  │              ▼               │
│  │              │    │   Check      │    ┌──────────────────────┐  │
│  └──────────────┘    └──────────────┘    │   ActiveScanner      │  │
│                                          │  (RLS bypass tests)  │  │
│  ┌──────────────────────────────────┐    └──────────────────────┘  │
│  │         ScannerPanel (UI)        │              │               │
│  │  ┌────────────┐ ┌─────────────┐  │              ▼               │
│  │  │ Instances  │ │ Vulnerable  │  │    ┌──────────────────────┐  │
│  │  │   Table    │ │   Tables    │  │    │SensitiveFieldAnalyzer│  │
│  │  └────────────┘ └─────────────┘  │    └──────────────────────┘  │
│  └──────────────────────────────────┘                              │
└─────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. SupabaseRlsScanner (Entry Point)

**File**: `SupabaseRlsScanner.java`

The main extension class implementing `BurpExtension`. Responsibilities:

- Initialize all components (config, stores, scanners, UI)
- Register HTTP handler for passive scanning
- Register scan check for Burp Scanner integration
- Register UI tab in Burp Suite
- Handle extension unloading and cleanup

```java
public void initialize(MontoyaApi api) {
    api.http().registerHttpHandler(passiveScanner);
    api.scanner().registerScanCheck(scanCheck);
    api.userInterface().registerSuiteTab(EXTENSION_NAME, scannerPanel);
}
```

### 2. PassiveScanner (HTTP Handler)

**File**: `scanner/PassiveScanner.java`

Implements `HttpHandler` to monitor all HTTP responses. Detection flow:

1. **Response Filtering**: Only analyze 2xx responses with text content types
2. **URL Extraction**: Use `PatternMatcher.extractSupabaseUrls()` to find Supabase URLs
3. **JWT Extraction**: Use `PatternMatcher.extractJwtTokens()` to find potential tokens
4. **JWT Validation**: Validate each JWT using `PatternMatcher.validateSupabaseJwt()`
5. **Instance Storage**: Store valid (URL, JWT) pairs in `InstanceStore`

```java
@Override
public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
    Set<String> urls = PatternMatcher.extractSupabaseUrls(body);
    List<String> jwts = PatternMatcher.extractJwtTokens(body);
    // Validate and store...
}
```

### 3. ActiveScanner (RLS Testing)

**File**: `scanner/ActiveScanner.java`

Performs active security testing against discovered Supabase instances:

#### Table Enumeration

Uses PostgREST OpenAPI endpoint to discover tables:
```
GET {base_url}/rest/v1/
Headers:
  apikey: {jwt_token}
  Authorization: Bearer {jwt_token}
```

#### Read Access Testing

Tests each table for SELECT access:
```
GET {base_url}/rest/v1/{table_name}?limit=100
```

#### Write Access Testing

Dry-run POST to test INSERT permissions:
```
POST {base_url}/rest/v1/{table_name}
Headers: Prefer: return=minimal
Body: {}
```

### 4. PatternMatcher (Detection Patterns)

**File**: `utils/PatternMatcher.java`

Centralized regex patterns for detection:

#### Supabase URL Patterns
```java
// Cloud instances
Pattern.compile("https://[a-z0-9-]+\\.supabase\\.co")

// Environment variable patterns
Pattern.compile("NEXT_PUBLIC_SUPABASE_URL[\"']?\\s*[:=]\\s*[\"']?(https://[^\"'\\s]+)")
Pattern.compile("VITE_SUPABASE_URL[\"']?\\s*[:=]\\s*[\"']?(https://[^\"'\\s]+)")
Pattern.compile("REACT_APP_SUPABASE_URL[\"']?\\s*[:=]\\s*[\"']?(https://[^\"'\\s]+)")
```

#### JWT Validation
Supabase JWTs must have:
- Valid 3-part JWT structure (header.payload.signature)
- `iss` claim = "supabase"
- `role` claim = "anon" or "service_role"
- Valid `ref` claim (project reference)

```java
public static String validateSupabaseJwt(String jwt) {
    // Decode payload, check iss, role, ref claims
    // Return null if valid, error message if invalid
}
```

### 5. SensitiveFieldAnalyzer

**File**: `utils/SensitiveFieldAnalyzer.java`

Analyzes table data for sensitive field exposure:

#### Field Name Analysis
Matches column names against severity-categorized patterns:
- **CRITICAL**: password, secret, api_key, credit_card, ssn
- **HIGH**: email, phone, bank_account, salary, auth
- **MEDIUM**: address, location, birth_date, device_id

#### Value Pattern Analysis
Examines actual field values for sensitive data patterns:
```java
// JWT tokens in any field
Pattern.compile("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")

// Credit card numbers
Pattern.compile("\\b(?:\\d{4}[-\\s]?){3}\\d{4}\\b")

// Email addresses (only in email-named fields)
Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
```

### 6. InstanceStore (State Management)

**File**: `core/InstanceStore.java`

Thread-safe storage for discovered Supabase instances:

- **Deduplication**: Tracks seen JWT tokens to avoid duplicates
- **Event Listeners**: Notifies UI of new instances and updates
- **Instance Updates**: Merges new JWT tokens with existing instances

### 7. ScannerPanel (User Interface)

**File**: `ui/ScannerPanel.java`

Swing-based UI panel registered as a Burp Suite tab:

#### Layout Structure
```
┌─────────────────────────────────────────────────────────────────────┐
│                    Discovered Supabase Instances                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  URL        │ JWT Present │ Tables │ Last Seen                 │ │
│  │─────────────────────────────────────────────────────────────── │ │
│  │  https://... │     ✓      │   12   │ 2024-01-04 10:30         │ │
│  └────────────────────────────────────────────────────────────────┘ │
│  [Test RLS] [Clear All] [Export]                                    │
├─────────────────────────────────────────────────────────────────────┤
│  Vulnerable Tables              │  Status                          │
│  ┌────────────────────────────┐ │ ┌────────────────────────────┐  │
│  │ Table │Severity│Rows│RLS  │ │ │ 10:30 - Discovered: ...    │  │
│  │───────────────────────────│ │ │ 10:31 - Scanning: ...      │  │
│  │ users │ HIGH   │ 50 │ Off │ │ │ 10:32 - Found 5 tables    │  │
│  └────────────────────────────┘ │ └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Flow

### Passive Detection Flow

```
HTTP Response
    │
    ▼
PassiveScanner.handleHttpResponseReceived()
    │
    ├──▶ PatternMatcher.extractSupabaseUrls(body)
    │         │
    │         ▼
    │    Set<String> supabaseUrls
    │
    ├──▶ PatternMatcher.extractJwtTokens(body)
    │         │
    │         ▼
    │    List<String> jwtTokens
    │
    ├──▶ PatternMatcher.validateSupabaseJwt(jwt) [for each JWT]
    │         │
    │         ▼
    │    Filter valid Supabase JWTs
    │
    └──▶ InstanceStore.addOrUpdate(url, jwt, source, reason)
              │
              ▼
         ScannerPanel UI Updated
```

### Active Testing Flow

```
User clicks "Test RLS"
    │
    ▼
ActiveScanner.scanInstance(instance)
    │
    ├──▶ Enumerate tables via REST API
    │         │
    │         ▼
    │    List<String> tableNames
    │
    ├──▶ For each table:
    │    │
    │    ├──▶ testTable(instance, tableName)
    │    │         │
    │    │         ▼
    │    │    GET /rest/v1/{table}?limit=100
    │    │         │
    │    │         ▼
    │    │    Parse JSON response
    │    │
    │    ├──▶ SensitiveFieldAnalyzer.analyzeTableData(rows)
    │    │         │
    │    │         ▼
    │    │    Map<String, FieldAnalysis> analysis
    │    │
    │    └──▶ testWriteAccess(instance, tableName)
    │              │
    │              ▼
    │         POST /rest/v1/{table} (empty body)
    │
    └──▶ Return ScanResult with all VulnerableTables
              │
              ▼
         UI displays results
```

## API Integration

### Supabase PostgREST API

The extension interacts with Supabase via the PostgREST REST API:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/rest/v1/` | GET | OpenAPI schema (table enumeration) |
| `/rest/v1/{table}?limit=N` | GET | Read table data |
| `/rest/v1/{table}` | POST | Test write access |

### Required Headers

```http
apikey: {anon_or_service_role_jwt}
Authorization: Bearer {jwt_token}
Content-Type: application/json
Prefer: return=minimal  (for POST requests)
```

## Security Model

### JWT Token Roles

| Role | Access Level | Risk if Exposed |
|------|-------------|-----------------|
| `anon` | Anonymous/public access | Medium - limited to RLS-allowed data |
| `service_role` | Full admin access | CRITICAL - bypasses all RLS policies |

### RLS Bypass Indicators

The extension identifies RLS bypasses when:
1. Anonymous JWT can read table data without restrictions
2. Row counts exceed expected public data limits
3. Sensitive columns (email, password, etc.) are accessible
4. Write operations succeed for anonymous users

## Build System

### Gradle Configuration

The project uses Gradle with Shadow plugin for fat JAR creation:

```groovy
plugins {
    id 'java'
    id 'com.github.johnrengelman.shadow' version '8.1.1'
}

dependencies {
    compileOnly 'net.portswigger.burp.extensions:montoya-api:2023.12.1'
}

shadowJar {
    archiveBaseName.set('supabase-rls-scanner')
    archiveVersion.set('1.0.0')
}
```

### Service Provider Configuration

The extension is registered via SPI:
```
src/main/resources/META-INF/services/burp.api.montoya.BurpExtension
```

Contents:
```
com.supabase.rlsscanner.SupabaseRlsScanner
```

