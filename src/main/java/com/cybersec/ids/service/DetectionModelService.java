package com.cybersec.ids.service;

import com.cybersec.ids.model.Alert;
import com.cybersec.ids.repository.AlertRepository;
import com.cybersec.waf.service.IpFirewallService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class DetectionModelService {
    private static final Logger log = LoggerFactory.getLogger(DetectionModelService.class);

    private final AlertRepository alertRepository;
    private final IpFirewallService firewallService;
    private boolean isTrainingEnabled = true;

    @Autowired
    public DetectionModelService(AlertRepository alertRepository, IpFirewallService firewallService) {
        this.alertRepository = alertRepository;
        this.firewallService = firewallService;
    }

    public void setTrainingEnabled(boolean enabled) {
        this.isTrainingEnabled = enabled;
        log.info("Detection Model Training: {}", enabled ? "ENABLED" : "DISABLED");
    }

    public boolean isTrainingEnabled() {
        return isTrainingEnabled;
    }

    /**
     * Periodically "train" on recent alerts to identify repeat offenders and block them.
     */
    @Scheduled(fixedDelay = 60000) // Run every minute
    public void trainAndMitigate() {
        if (!isTrainingEnabled) return;

        log.info("Starting detection model training cycle...");
        LocalDateTime since = LocalDateTime.now().minusHours(24);
        List<Alert> recentAlerts = alertRepository.findByDetectedAtAfter(since);

        if (recentAlerts.isEmpty()) {
            log.info("No recent alerts to train on.");
            return;
        }

        // Group by IP and count attacks
        Map<String, Long> attackCounts = recentAlerts.stream()
                .collect(Collectors.groupingBy(Alert::getSourceIp, Collectors.counting()));

        // Auto-blocking logic: if more than 5 alerts in 24 hours, block the IP
        attackCounts.forEach((ip, count) -> {
            if ("0:0:0:0:0:0:0:1".equals(ip) || "127.0.0.1".equals(ip)) return; // Never block localhost
            if (count >= 5) {
                log.warn("ML Model identified {} as a frequent attacker ({} alerts). Auto-blocking...", ip, count);
                firewallService.blockIp(ip, "Auto-blocked by ML Detection Model (Reason: Frequency > 5)", null);
            }
        });

        log.info("Training cycle complete. Processed {} alerts.", recentAlerts.size());
    }
}
