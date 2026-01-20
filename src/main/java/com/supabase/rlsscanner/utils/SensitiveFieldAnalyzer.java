/*
 * Supabase RLS Security Scanner - Burp Suite Extension
 * Sensitive field analysis utilities
 */

package com.supabase.rlsscanner.utils;

import com.supabase.rlsscanner.models.FieldAnalysis;
import com.supabase.rlsscanner.models.Severity;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Analyzer for detecting sensitive fields in table data.
 */
public class SensitiveFieldAnalyzer {
    
    // Critical severity patterns - passwords, secrets, tokens
    private static final List<Pattern> CRITICAL_PATTERNS = Arrays.asList(
        Pattern.compile("\\bpassword\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bpasswd\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bpwd\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bsecret\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bapi[_-]?key\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bapikey\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bprivate[_-]?key\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bsecret[_-]?key\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\btoken\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bjwt\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\baccess[_-]?token\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\brefresh[_-]?token\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcredit[_-]?card\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcard[_-]?number\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcvv\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcvc\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bssn\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bsocial[_-]?security\\b", Pattern.CASE_INSENSITIVE)
    );
    
    // High severity patterns - PII, financial
    private static final List<Pattern> HIGH_PATTERNS = Arrays.asList(
        Pattern.compile("\\bemail\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bphone\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bphone[_-]?number\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bmobile\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bdriver[_-]?license\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bpassport[_-]?number\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bnational[_-]?id\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\btax[_-]?id\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bbank[_-]?account\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\baccount[_-]?number\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\brouting[_-]?number\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\biban\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bswift[_-]?code\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bsalary\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bincome\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bpayroll\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bauth\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bauth[_-]?key\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bsession[_-]?id\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bsession[_-]?token\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\brecovery[_-]?code\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\botp\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b2fa\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\buser[_-]?id\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcustomer[_-]?id\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bpatient[_-]?id\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bmedical[_-]?record\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bdiagnosis\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\binsurance[_-]?number\\b", Pattern.CASE_INSENSITIVE)
    );
    
    // Medium severity patterns - addresses, device IDs
    private static final List<Pattern> MEDIUM_PATTERNS = Arrays.asList(
        Pattern.compile("\\baddress\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bstreet\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bzip\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bpostal[_-]?code\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bhome[_-]?address\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bbilling[_-]?address\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bip[_-]?address\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\blocation\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcoordinates\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\blatitude\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\blongitude\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bbirth[_-]?date\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bdob\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bdevice[_-]?id\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bmac[_-]?address\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bimei\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bserial[_-]?number\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bfingerprint\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bbiometric\\b", Pattern.CASE_INSENSITIVE)
    );
    
    // Non-sensitive field patterns (exclusion list)
    private static final List<Pattern> NON_SENSITIVE_PATTERNS = Arrays.asList(
        Pattern.compile("\\bcreated[_-]?at\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bupdated[_-]?at\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bdeleted[_-]?at\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("^id$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bdescription\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\btitle\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("^name$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcontent\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcreator\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bauthor\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\blinks?\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\burl\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bimage\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bavatar\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bsearch[_-]?vector\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bvector\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bauthor[_-]?links\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bexample[_-]?emails\\b", Pattern.CASE_INSENSITIVE)
    );
    
    /**
     * Check if a field name is non-sensitive (in exclusion list).
     */
    public static boolean isNonSensitiveField(String fieldName) {
        if (fieldName == null) return true;
        
        for (Pattern pattern : NON_SENSITIVE_PATTERNS) {
            if (pattern.matcher(fieldName).find()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Determine the severity of a sensitive field.
     */
    public static Severity getFieldSeverity(String fieldName) {
        if (fieldName == null || isNonSensitiveField(fieldName)) {
            return Severity.NONE;
        }

        for (Pattern pattern : CRITICAL_PATTERNS) {
            if (pattern.matcher(fieldName).find()) {
                return Severity.CRITICAL;
            }
        }

        for (Pattern pattern : HIGH_PATTERNS) {
            if (pattern.matcher(fieldName).find()) {
                return Severity.HIGH;
            }
        }

        for (Pattern pattern : MEDIUM_PATTERNS) {
            if (pattern.matcher(fieldName).find()) {
                return Severity.MEDIUM;
            }
        }

        return Severity.NONE;
    }

    /**
     * Check if a field name indicates sensitive data.
     */
    public static boolean isSensitiveFieldName(String fieldName) {
        return getFieldSeverity(fieldName) != Severity.NONE;
    }

    /**
     * Analyze a field value for sensitive data patterns.
     * Returns the detection reason if found.
     */
    public static String analyzeValueForSensitiveData(String fieldName, String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }

        String fieldLower = fieldName.toLowerCase();

        // Check for JWT tokens (always sensitive)
        if (PatternMatcher.JWT_PATTERN.matcher(value).find()) {
            return "jwt_pattern";
        }

        // Check for credit card patterns (always sensitive)
        if (PatternMatcher.CREDIT_CARD_PATTERN.matcher(value).find()) {
            return "credit_card_pattern";
        }

        // Check for email addresses - only flag if field name contains "email"
        if (fieldLower.contains("email") && PatternMatcher.EMAIL_PATTERN.matcher(value).find()) {
            return "email_pattern";
        }

        // Check for phone numbers - only flag if field name suggests phone
        if ((fieldLower.contains("phone") || fieldLower.contains("mobile")) &&
            PatternMatcher.PHONE_PATTERN.matcher(value).find()) {
            String digits = value.replaceAll("[^0-9]", "");
            if (digits.length() >= 10) {
                return "phone_pattern";
            }
        }

        return null;
    }

    /**
     * Analyze table rows and return field analysis results.
     */
    public static Map<String, FieldAnalysis> analyzeTableData(
            List<Map<String, Object>> rows, int maxSamples) {

        Map<String, FieldAnalysis> results = new HashMap<>();

        if (rows == null || rows.isEmpty()) {
            return results;
        }

        // Get field names from first row
        Map<String, Object> firstRow = rows.get(0);
        if (firstRow == null) {
            return results;
        }

        Set<String> fieldNames = firstRow.keySet();
        int sampleSize = Math.min(rows.size(), maxSamples);

        for (String fieldName : fieldNames) {
            // Skip non-sensitive fields
            if (isNonSensitiveField(fieldName)) {
                continue;
            }

            List<String> detectionReasons = new ArrayList<>();
            Severity fieldSeverity = getFieldSeverity(fieldName);

            // Check if field name is sensitive
            if (fieldSeverity != Severity.NONE) {
                detectionReasons.add("field_name");
            }

            // Sample values for pattern analysis
            int nonNullCount = 0;
            for (int i = 0; i < sampleSize && i < rows.size(); i++) {
                Object value = rows.get(i).get(fieldName);
                if (value != null) {
                    nonNullCount++;
                    String valueStr = value.toString();
                    String valueReason = analyzeValueForSensitiveData(fieldName, valueStr);
                    if (valueReason != null && !detectionReasons.contains(valueReason)) {
                        detectionReasons.add(valueReason);
                        // Upgrade severity based on value patterns
                        if (valueReason.equals("jwt_pattern") || valueReason.equals("credit_card_pattern")) {
                            if (fieldSeverity.getPriority() < Severity.CRITICAL.getPriority()) {
                                fieldSeverity = Severity.CRITICAL;
                            }
                        } else if (valueReason.equals("email_pattern") || valueReason.equals("phone_pattern")) {
                            if (fieldSeverity.getPriority() < Severity.HIGH.getPriority()) {
                                fieldSeverity = Severity.HIGH;
                            }
                        }
                    }
                }
            }

            // Only add if we found reasons
            if (!detectionReasons.isEmpty()) {
                results.put(fieldName, new FieldAnalysis(
                    fieldName, detectionReasons, nonNullCount, fieldSeverity
                ));
            }
        }

        return results;
    }

    /**
     * Determine overall table severity from field analysis.
     */
    public static Severity determineTableSeverity(Map<String, FieldAnalysis> fieldAnalysis) {
        return fieldAnalysis.values().stream()
            .map(FieldAnalysis::getSeverity)
            .filter(s -> s != Severity.NONE)
            .max((s1, s2) -> Integer.compare(s1.getPriority(), s2.getPriority()))
            .orElse(Severity.NONE);
    }

    // PII patterns (Personally Identifiable Information)
    private static final List<Pattern> PII_PATTERNS = Arrays.asList(
        Pattern.compile("\\bemail\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bphone\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bmobile\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\baddress\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bssn\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bsocial[_-]?security\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bdriver[_-]?license\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bpassport\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bnational[_-]?id\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bbirth[_-]?date\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bdob\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bfirst[_-]?name\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\blast[_-]?name\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bfull[_-]?name\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\buser[_-]?id\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcustomer[_-]?id\\b", Pattern.CASE_INSENSITIVE)
    );

    // PCI patterns (Payment Card Industry data)
    private static final List<Pattern> PCI_PATTERNS = Arrays.asList(
        Pattern.compile("\\bcredit[_-]?card\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcard[_-]?number\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcvv\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bcvc\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bpan\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bexpir\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bbank[_-]?account\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\baccount[_-]?number\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\brouting[_-]?number\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\biban\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bswift\\b", Pattern.CASE_INSENSITIVE)
    );

    // Secrets patterns (API keys, tokens, passwords)
    private static final List<Pattern> SECRETS_PATTERNS = Arrays.asList(
        Pattern.compile("\\bpassword\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bpasswd\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bpwd\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bsecret\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bapi[_-]?key\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bprivate[_-]?key\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\btoken\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bjwt\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\baccess[_-]?token\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\brefresh[_-]?token\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bauth[_-]?key\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bsession[_-]?id\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\botp\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\b2fa\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\brecovery[_-]?code\\b", Pattern.CASE_INSENSITIVE)
    );

    /**
     * Check if any field in the analysis matches PII patterns.
     */
    public static boolean hasPiiData(Map<String, FieldAnalysis> fieldAnalysis) {
        for (String fieldName : fieldAnalysis.keySet()) {
            for (Pattern pattern : PII_PATTERNS) {
                if (pattern.matcher(fieldName).find()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check if any field in the analysis matches PCI patterns.
     */
    public static boolean hasPciData(Map<String, FieldAnalysis> fieldAnalysis) {
        for (String fieldName : fieldAnalysis.keySet()) {
            for (Pattern pattern : PCI_PATTERNS) {
                if (pattern.matcher(fieldName).find()) {
                    return true;
                }
            }
        }
        // Also check for credit card patterns in detection reasons
        for (FieldAnalysis analysis : fieldAnalysis.values()) {
            if (analysis.getDetectionReasons().contains("credit_card_pattern")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if any field in the analysis matches Secrets patterns.
     */
    public static boolean hasSecretsData(Map<String, FieldAnalysis> fieldAnalysis) {
        for (String fieldName : fieldAnalysis.keySet()) {
            for (Pattern pattern : SECRETS_PATTERNS) {
                if (pattern.matcher(fieldName).find()) {
                    return true;
                }
            }
        }
        // Also check for JWT patterns in detection reasons
        for (FieldAnalysis analysis : fieldAnalysis.values()) {
            if (analysis.getDetectionReasons().contains("jwt_pattern")) {
                return true;
            }
        }
        return false;
    }

    private SensitiveFieldAnalyzer() {
        // Utility class
    }
}

