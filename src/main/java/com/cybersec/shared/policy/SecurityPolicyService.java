package com.cybersec.shared.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Automating Security Policy Enforcement (IPS/WAF dynamic rules)
 */
@Service
public class SecurityPolicyService {
    private static final Logger logger = LoggerFactory.getLogger(SecurityPolicyService.class);
    
    // IP -> Expiry Time
    private final Map<String, LocalDateTime> blacklistedIps = new ConcurrentHashMap<>();
    private final Set<String> activeRules = ConcurrentHashMap.newKeySet();

    public void enforcePolicy(String sourceIp, double threatScore, String reason) {
        if (threatScore > 0.8) {
            blockIp(sourceIp, 60, "High ML Threat Score: " + reason);
        } else if (threatScore > 0.5) {
            monitorIp(sourceIp, "Suspicious Activity Detected");
        }
    }

    private void blockIp(String ip, int minutes, String reason) {
        LocalDateTime expiry = LocalDateTime.now().plusMinutes(minutes);
        blacklistedIps.put(ip, expiry);
        activeRules.add("BLOCK " + ip + " (Reason: " + reason + ")");
        logger.warn("AUTOMATED POLICY ENFORCEMENT: Blocking IP {} for {} minutes. Reason: {}", ip, minutes, reason);
    }

    private void monitorIp(String ip, String reason) {
        activeRules.add("WATCH " + ip + " (Reason: " + reason + ")");
        logger.info("AUTOMATED POLICY ENFORCEMENT: Monitoring IP {}. Reason: {}", ip, reason);
    }

    public boolean isIpBlocked(String ip) {
        LocalDateTime expiry = blacklistedIps.get(ip);
        if (expiry == null) return false;
        
        if (LocalDateTime.now().isAfter(expiry)) {
            blacklistedIps.remove(ip);
            activeRules.removeIf(r -> r.contains(ip));
            return false;
        }
        return true;
    }

    public Set<String> getActiveRules() {
        return activeRules;
    }
}
