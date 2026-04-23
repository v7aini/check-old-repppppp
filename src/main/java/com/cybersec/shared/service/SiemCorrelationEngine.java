package com.cybersec.shared.service;

import com.cybersec.ids.model.Alert;
import com.cybersec.ids.repository.AlertRepository;
import com.cybersec.ids.service.AlertService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class SiemCorrelationEngine {
    private static final Logger log = LoggerFactory.getLogger(SiemCorrelationEngine.class);
    private final AlertRepository alertRepo;
    private final AlertService alertService;

    @Autowired
    public SiemCorrelationEngine(AlertRepository alertRepo, @Lazy AlertService alertService) {
        this.alertRepo = alertRepo;
        this.alertService = alertService;
    }

    @Scheduled(fixedDelay = 60000) // Run every minute
    public void correlate() {
        LocalDateTime window = LocalDateTime.now().minusMinutes(10);
        List<Alert> recentAlerts = alertRepo.findByDetectedAtAfter(window);
        
        // Group alerts by Source IP
        Map<String, Set<String>> ipModules = new HashMap<>();
        for (Alert a : recentAlerts) {
            ipModules.computeIfAbsent(a.getSourceIp(), k -> new java.util.HashSet<>()).add(a.getDetectedBy());
        }

        // If an IP is flagged by 3 or more different modules, it's a high-confidence threat
        for (Map.Entry<String, Set<String>> entry : ipModules.entrySet()) {
            if (entry.getValue().size() >= 3) {
                String ip = entry.getKey();
                String modules = String.join(", ", entry.getValue());
                
                // Check if we already fired a correlation alert recently for this IP
                boolean alreadyFired = recentAlerts.stream()
                        .anyMatch(a -> a.getSourceIp().equals(ip) && a.getAttackType().equals("SIEM_CORRELATED"));
                
                if (!alreadyFired) {
                    alertService.fireAlert(ip, "SIEM_CORRELATED",
                            "Multi-stage attack pattern detected. Flagged by modules: [" + modules + "]",
                            "SIEM_ENGINE", "CRITICAL");
                    log.info("[SIEM] Correlated threat detected from {}: {}", ip, modules);
                }
            }
        }
    }
}
