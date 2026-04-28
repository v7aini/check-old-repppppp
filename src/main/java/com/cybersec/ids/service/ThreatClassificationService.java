package com.cybersec.ids.service;

import com.cybersec.ids.model.AttackPattern;
import com.cybersec.ids.model.AttackPattern.ThreatLevel;
import com.cybersec.ids.model.ThreatClassification;
import com.cybersec.ids.model.ThreatClassification.*;
import com.cybersec.ids.repository.AttackPatternRepository;
import com.cybersec.ids.repository.ThreatClassificationRepository;
import com.cybersec.waf.service.IpFirewallService;
import com.cybersec.waf.service.RateLimiterService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * AI-driven Threat Classification Service.
 *
 * Analyses every incoming request against:
 *   1. Regex-based payload signatures (SQL injection, XSS, traversal, etc.)
 *   2. Previously-learned attack patterns stored in the database
 *   3. Brute-force / DDoS frequency heuristics
 *   4. IP reputation (prior classifications + firewall state)
 *
 * Each request is classified as SAFE, SUSPICIOUS, or MALICIOUS with a
 * confidence score.  Appropriate automatic actions (logging, rate-limiting,
 * blocking, alerting) are taken.
 */
@Service
public class ThreatClassificationService {

    private static final Logger log = LoggerFactory.getLogger(ThreatClassificationService.class);

    private final AttackPatternRepository patternRepo;
    private final ThreatClassificationRepository classificationRepo;
    private final AlertService alertService;
    private final IpFirewallService firewallService;
    private final RateLimiterService rateLimiterService;

    // ---- Real-time tracking maps ----
    private final ConcurrentHashMap<String, AtomicInteger> recentRequestCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicInteger> failedLoginCounts   = new ConcurrentHashMap<>();

    // ---- Compiled regex patterns for inline classification ----
    private static final List<AttackSignature> SIGNATURES = List.of(
        // SQL Injection patterns
        new AttackSignature("SQL_INJECTION",
            Pattern.compile("(?i)(union\\s+select|select\\s+.*from|insert\\s+into|delete\\s+from|drop\\s+table|update\\s+.*set|1\\s*=\\s*1|'\\s*or\\s*'|--\\s|;\\s*drop|benchmark\\s*\\(|sleep\\s*\\(|load_file|into\\s+outfile)", Pattern.CASE_INSENSITIVE),
            0.92),
        // XSS patterns
        new AttackSignature("XSS",
            Pattern.compile("(?i)(<script|javascript:|onerror\\s*=|onload\\s*=|onclick\\s*=|onmouseover\\s*=|<iframe|<object|<embed|alert\\s*\\(|document\\.cookie|document\\.write|eval\\s*\\()", Pattern.CASE_INSENSITIVE),
            0.88),
        // Path traversal
        new AttackSignature("PATH_TRAVERSAL",
            Pattern.compile("(\\.\\.[\\\\/]){2,}|/etc/passwd|/etc/shadow|%2e%2e|%252e%252e", Pattern.CASE_INSENSITIVE),
            0.90),
        // Command injection
        new AttackSignature("COMMAND_INJECTION",
            Pattern.compile("(?i)(;\\s*cat\\s|;\\s*ls\\s|;\\s*rm\\s|\\|\\s*cat|`.*`|\\$\\(.*\\)|/bin/(bash|sh)|cmd\\.exe|powershell)", Pattern.CASE_INSENSITIVE),
            0.93),
        // LDAP injection
        new AttackSignature("LDAP_INJECTION",
            Pattern.compile("(?i)(\\)\\(|\\(\\|\\(|\\(\\&\\(|\\*\\)\\(|\\)\\(\\|)", Pattern.CASE_INSENSITIVE),
            0.85),
        // Log4Shell / JNDI
        new AttackSignature("LOG4SHELL",
            Pattern.compile("\\$\\{jndi:|\\$\\{lower:|\\$\\{upper:|\\$\\{env:", Pattern.CASE_INSENSITIVE),
            0.98)
    );

    // Brute-force thresholds
    private static final int BRUTE_FORCE_THRESHOLD       = 10;
    private static final int DDOS_REQUESTS_PER_10SEC     = 80;

    @Autowired
    public ThreatClassificationService(AttackPatternRepository patternRepo,
                                       ThreatClassificationRepository classificationRepo,
                                       @Lazy AlertService alertService,
                                       IpFirewallService firewallService,
                                       RateLimiterService rateLimiterService) {
        this.patternRepo = patternRepo;
        this.classificationRepo = classificationRepo;
        this.alertService = alertService;
        this.firewallService = firewallService;
        this.rateLimiterService = rateLimiterService;
    }

    // ====================================================================
    //  PRIMARY CLASSIFICATION ENTRY POINT
    // ====================================================================

    /**
     * Classifies an incoming HTTP request.  Called from the IDS interceptor.
     *
     * @return the persisted ThreatClassification record
     */
    @Transactional
    public ThreatClassification classifyRequest(String clientIp,
                                                 String uri,
                                                 String queryString,
                                                 String method,
                                                 String userAgent,
                                                 String body) {
        long start = System.currentTimeMillis();

        // 1. Build the "payload" string to scan
        StringBuilder payload = new StringBuilder();
        if (uri        != null) payload.append(uri).append(" ");
        if (queryString!= null) payload.append(queryString).append(" ");
        if (body       != null) payload.append(body).append(" ");
        if (userAgent  != null) payload.append(userAgent);
        String fullPayload = payload.toString();

        // 2. Run signature analysis
        Classification result  = Classification.SAFE;
        double         confidence = 0.0;
        String         attackType = null;
        Long           matchedPatternId = null;

        for (AttackSignature sig : SIGNATURES) {
            if (sig.pattern.matcher(fullPayload).find()) {
                result     = Classification.MALICIOUS;
                confidence = sig.baseConfidence;
                attackType = sig.type;
                break;
            }
        }

        // 3. Check against previously-learned attack patterns (from DB)
        if (result == Classification.SAFE) {
            String hash = computePayloadHash(fullPayload);
            Optional<AttackPattern> known = patternRepo.findBySignatureHash(hash);
            if (known.isPresent()) {
                AttackPattern ap = known.get();
                ap.recordHit(ap.getAvgThreatScore());
                patternRepo.save(ap);
                matchedPatternId = ap.getId();

                if (ap.getThreatLevel() == ThreatLevel.MALICIOUS) {
                    result     = Classification.MALICIOUS;
                    confidence = ap.getAvgThreatScore();
                    attackType = ap.getAttackType();
                } else if (ap.getThreatLevel() == ThreatLevel.SUSPICIOUS) {
                    result     = Classification.SUSPICIOUS;
                    confidence = ap.getAvgThreatScore();
                    attackType = ap.getAttackType();
                }
            }
        }

        // 4. Brute-force login detection (only count POST requests to login endpoints)
        if (result == Classification.SAFE && "POST".equalsIgnoreCase(method) && isLoginEndpoint(uri)) {
            int loginAttempts = failedLoginCounts
                    .computeIfAbsent(clientIp, k -> new AtomicInteger())
                    .incrementAndGet();
            if (loginAttempts >= BRUTE_FORCE_THRESHOLD) {
                result     = Classification.MALICIOUS;
                confidence = 0.87;
                attackType = "BRUTE_FORCE";
            } else if (loginAttempts >= BRUTE_FORCE_THRESHOLD / 2) {
                result     = Classification.SUSPICIOUS;
                confidence = 0.55;
                attackType = "BRUTE_FORCE_ATTEMPT";
            }
        }

        // 5. DDoS-like frequency detection
        if (result == Classification.SAFE) {
            int count = recentRequestCounts
                    .computeIfAbsent(clientIp, k -> new AtomicInteger())
                    .incrementAndGet();
            if (count >= DDOS_REQUESTS_PER_10SEC) {
                result     = Classification.MALICIOUS;
                confidence = 0.82;
                attackType = "DDOS_FLOOD";
            } else if (count >= DDOS_REQUESTS_PER_10SEC / 2) {
                result     = Classification.SUSPICIOUS;
                confidence = 0.45;
                attackType = "HIGH_FREQUENCY";
            }
        }

        // 6. Unauthorized API access (no user-agent or suspicious patterns)
        if (result == Classification.SAFE && uri != null && uri.startsWith("/api/")) {
            if (userAgent == null || userAgent.isBlank()) {
                result     = Classification.SUSPICIOUS;
                confidence = 0.50;
                attackType = "UNAUTHORIZED_API_ACCESS";
            }
        }

        // 7. Determine action
        ActionTaken action = ActionTaken.ALLOWED;
        switch (result) {
            case MALICIOUS:
                if (confidence >= 0.80) {
                    firewallService.blockIp(clientIp,
                        "AI Security Assistant – auto-blocked: " + attackType,
                        LocalDateTime.now().plusHours(1));
                    action = ActionTaken.BLOCKED;
                } else {
                    action = ActionTaken.RATE_LIMITED;
                }
                alertService.fireAlert(clientIp, attackType,
                    String.format("[AI-SEC] %s detected (confidence: %.2f). Payload: %s",
                        attackType, confidence,
                        fullPayload.substring(0, Math.min(fullPayload.length(), 200))),
                    "AI_SECURITY_ASSISTANT",
                    confidence >= 0.90 ? "CRITICAL" : "HIGH");
                break;

            case SUSPICIOUS:
                if (!rateLimiterService.isAllowed(clientIp)) {
                    action = ActionTaken.RATE_LIMITED;
                } else {
                    action = ActionTaken.ALERT_ONLY;
                }
                alertService.fireAlert(clientIp, attackType,
                    String.format("[AI-SEC] Suspicious activity: %s (confidence: %.2f)",
                        attackType, confidence),
                    "AI_SECURITY_ASSISTANT", "MEDIUM");
                break;

            default:
                action = ActionTaken.ALLOWED;
        }

        // 8. Learn new pattern if it was malicious
        if (result == Classification.MALICIOUS && matchedPatternId == null) {
            learnNewPattern(fullPayload, attackType, confidence);
        }

        // 9. Persist classification record
        long elapsed = System.currentTimeMillis() - start;
        ThreatClassification tc = ThreatClassification.builder()
                .clientIp(clientIp)
                .requestUri(uri)
                .requestPayload(fullPayload.length() > 2000 ? fullPayload.substring(0, 2000) : fullPayload)
                .classification(result)
                .confidenceScore(confidence)
                .attackType(attackType)
                .matchedPatternId(matchedPatternId)
                .actionTaken(action)
                .responseTimeMs(elapsed)
                .build();
        classificationRepo.save(tc);

        if (result != Classification.SAFE) {
            log.warn("[AI-SEC] {} | {} | {} | conf:{} | action:{} | {}ms",
                clientIp, result, attackType, String.format("%.2f", confidence), action, elapsed);
        }

        return tc;
    }

    // ====================================================================
    //  PATTERN LEARNING
    // ====================================================================

    private void learnNewPattern(String payload, String attackType, double score) {
        String hash = computePayloadHash(payload);
        if (patternRepo.findBySignatureHash(hash).isPresent()) return;

        AttackPattern ap = AttackPattern.builder()
                .attackType(attackType)
                .signatureHash(hash)
                .samplePayload(payload.length() > 1000 ? payload.substring(0, 1000) : payload)
                .threatLevel(score >= 0.85 ? ThreatLevel.MALICIOUS : ThreatLevel.SUSPICIOUS)
                .avgThreatScore(score)
                .autoBlockEnabled(score >= 0.85)
                .build();
        patternRepo.save(ap);
        log.info("[AI-SEC] Learned new attack pattern: {} (hash: {})", attackType, hash.substring(0, 12));
    }

    // ====================================================================
    //  REAL-TIME THREAT SUMMARY REPORT
    // ====================================================================

    public Map<String, Object> getThreatSummary() {
        LocalDateTime last24h = LocalDateTime.now().minusHours(24);
        Map<String, Object> summary = new LinkedHashMap<>();

        // 1. Classification breakdown
        Map<String, Long> classBreakdown = new LinkedHashMap<>();
        try {
            for (Object[] row : classificationRepo.countByClassificationSince(last24h)) {
                if (row != null && row.length >= 2 && row[0] != null) {
                    // Handle both String (EnumType.STRING) and Enum objects
                    String key = row[0].toString();
                    long val = ((Number) row[1]).longValue();
                    classBreakdown.put(key, val);
                }
            }
        } catch (Exception e) {
            log.error("Error fetching classification breakdown: {}", e.getMessage());
        }
        summary.put("classificationBreakdown", classBreakdown);

        // 2. Top attack types (Exclude SAFE traffic)
        Map<String, Long> topAttacks = new LinkedHashMap<>();
        try {
            // Using a more robust query approach or filtering safe results here
            for (Object[] row : classificationRepo.getTopAttackTypesSince(last24h, Classification.SAFE)) {
                if (row != null && row.length >= 2 && row[0] != null) {
                    topAttacks.put(row[0].toString(), ((Number) row[1]).longValue());
                }
            }
        } catch (Exception e) {
            log.error("Error fetching top attack types: {}", e.getMessage());
        }
        summary.put("topAttackTypes", topAttacks);

        // 3. Pattern intelligence
        summary.put("totalKnownPatterns",   patternRepo.count());
        summary.put("maliciousPatterns",    patternRepo.countByThreatLevel(ThreatLevel.MALICIOUS));
        summary.put("suspiciousPatterns",   patternRepo.countByThreatLevel(ThreatLevel.SUSPICIOUS));
        summary.put("autoBlockPatterns",    patternRepo.findByAutoBlockEnabledTrue().size());

        // 4. Top learned patterns
        List<Map<String, Object>> topPatterns = new ArrayList<>();
        try {
            List<AttackPattern> patterns = patternRepo.findTopPatterns();
            if (patterns != null) {
                for (AttackPattern ap : patterns.stream().limit(10).toList()) {
                    Map<String, Object> p = new LinkedHashMap<>();
                    p.put("id", ap.getId());
                    p.put("attackType", ap.getAttackType());
                    p.put("threatLevel", ap.getThreatLevel() != null ? ap.getThreatLevel().name() : "UNKNOWN");
                    p.put("hitCount", ap.getHitCount());
                    p.put("avgScore", String.format("%.2f", ap.getAvgThreatScore()));
                    p.put("lastSeen", ap.getLastSeen() != null ? ap.getLastSeen().toString() : LocalDateTime.now().toString());
                    p.put("autoBlock", ap.isAutoBlockEnabled());
                    topPatterns.add(p);
                }
            }
        } catch (Exception e) {
            log.error("Error fetching top learned patterns: {}", e.getMessage());
        }
        summary.put("topLearnedPatterns", topPatterns);

        // 5. Totals
        summary.put("totalClassifications24h", classificationRepo.countByClassifiedAtAfter(last24h));
        summary.put("totalBlocked",   classBreakdown.getOrDefault("MALICIOUS", 0L));
        summary.put("totalSuspicious", classBreakdown.getOrDefault("SUSPICIOUS", 0L));
        summary.put("totalSafe",       classBreakdown.getOrDefault("SAFE", 0L));

        return summary;
    }


    // ====================================================================
    //  BRUTE FORCE TRACKING
    // ====================================================================

    public void recordFailedLogin(String ip) {
        failedLoginCounts.computeIfAbsent(ip, k -> new AtomicInteger()).incrementAndGet();
    }

    public void clearFailedLogins(String ip) {
        failedLoginCounts.remove(ip);
    }

    // ====================================================================
    //  PERIODIC CLEANUP (called by DetectionModelService schedule or own schedule)
    // ====================================================================

    public void resetRequestCounters() {
        recentRequestCounts.clear();
    }

    // ====================================================================
    //  HELPERS
    // ====================================================================

    private boolean isLoginEndpoint(String uri) {
        if (uri == null) return false;
        return uri.contains("/login") || uri.contains("/auth") || uri.contains("/signin");
    }

    private String computePayloadHash(String payload) {
        try {
            // Normalize: lowercase, strip whitespace runs
            String normalized = payload.toLowerCase().replaceAll("\\s+", " ").trim();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(normalized.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : digest) hex.append(String.format("%02x", b));
            return hex.toString();
        } catch (Exception e) {
            return UUID.randomUUID().toString();
        }
    }

    // ---- inner class ----
    private static class AttackSignature {
        final String  type;
        final Pattern pattern;
        final double  baseConfidence;
        AttackSignature(String type, Pattern pattern, double baseConfidence) {
            this.type = type; this.pattern = pattern; this.baseConfidence = baseConfidence;
        }
    }
}
