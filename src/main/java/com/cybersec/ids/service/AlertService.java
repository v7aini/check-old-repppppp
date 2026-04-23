package com.cybersec.ids.service;

import com.cybersec.ids.model.Alert;
import com.cybersec.ids.model.Alert.AlertStatus;
import com.cybersec.ids.model.Alert.Severity;
import com.cybersec.ids.repository.AlertRepository;
import com.cybersec.telegram.TelegramAlertService;
import com.cybersec.shared.service.GeolocationService;
import com.cybersec.tip.service.ThreatScoringService;
import io.swagger.v3.oas.annotations.Operation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class AlertService {
    private static final Logger log = LoggerFactory.getLogger(AlertService.class);
    private final AlertRepository repo;
    private final SimpMessagingTemplate ws;
    private final ThreatScoringService tipService;
    private final TelegramAlertService telegramService;
    private final GeolocationService geoService;

    @Autowired
    public AlertService(AlertRepository repo,
                        @Lazy SimpMessagingTemplate ws,
        @Lazy ThreatScoringService tipService,
        @Lazy TelegramAlertService telegramService,
        GeolocationService geoService) {
    this.repo = repo; this.ws = ws;
    this.tipService = tipService;
    this.telegramService = telegramService;
    this.geoService = geoService;
}

    @Transactional
    public Alert fireAlert(String ip, String type, String detail, String by, String sevStr) {
        Severity sev;
        try { sev = Severity.valueOf(sevStr.toUpperCase()); } catch (Exception e) { sev = Severity.MEDIUM; }
        int score = 0;
        try { score = tipService.scoreIp(ip); } catch (Exception ignored) {}

        Map<String, Object> geo = geoService.getGeoData(ip);

        Alert a = Alert.builder().sourceIp(ip).attackType(type).detail(detail).detectedBy(by)
                .severity(score >= 80 ? Severity.CRITICAL : sev)
                .status(AlertStatus.OPEN).detectedAt(LocalDateTime.now())
                .threatScore(score)
                .country((String) geo.get("country"))
                .latitude((Double) geo.get("lat"))
                .longitude((Double) geo.get("lon"))
                .build();
        a = repo.save(a);
        log.warn("[IDS] #{} | {} | {} | score:{}", a.getId(), type, ip, score);

        // Broadcast via WebSocket to dashboard
        try {
            Map<String, Object> payload = new HashMap<>();
            payload.put("id", a.getId()); payload.put("sourceIp", ip); payload.put("attackType", type);
            payload.put("severity", a.getSeverity().name());
            payload.put("detectedBy", by != null ? by : "UNKNOWN");
            payload.put("detail", detail.substring(0, Math.min(detail.length(), 150)));
            payload.put("score", score); payload.put("timestamp", a.getDetectedAt().toString());
            payload.put("country", a.getCountry());
            payload.put("lat", a.getLatitude());
            payload.put("lon", a.getLongitude());
            ws.convertAndSend("/topic/ids-alerts", payload);
        } catch (Exception e) { log.debug("WS broadcast failed: {}", e.getMessage()); }

        // Send Telegram notification (async, non-blocking)
        try { telegramService.sendAlert(a); } catch (Exception ignored) {}

        return a;
    }

    public List<Alert> getRecentAlerts(int n)  { return repo.findTopNByOrderByDetectedAtDesc(n); }
    public List<Alert> getOpenAlerts()          { return repo.findByStatusOrderByDetectedAtDesc(AlertStatus.OPEN); }
    public List<Alert> getAlertsByIp(String ip) { return repo.findBySourceIpOrderByDetectedAtDesc(ip); }
    public Optional<Alert> findById(Long id)    { return repo.findById(id); }
    public long countAlertsToday()              { return repo.countByDetectedAtAfter(LocalDateTime.now().toLocalDate().atStartOfDay()); }
    public long countBySeverity(Severity s)     { return repo.countBySeverity(s); }
    public Map<String, Long> getAlertCountsByType() { return repo.countGroupedByAttackType(); }

    @Transactional
    public Alert updateStatus(Long id, AlertStatus status, String notes) {
        Alert a = repo.findById(id).orElseThrow(() -> new RuntimeException("Alert not found: " + id));
        a.setStatus(status); a.setNotes(notes);
        if (status == AlertStatus.RESOLVED) a.setResolvedAt(LocalDateTime.now());
        return repo.save(a);
    }
}
