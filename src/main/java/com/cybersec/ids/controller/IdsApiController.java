package com.cybersec.ids.controller;

import com.cybersec.ids.model.Alert;
import com.cybersec.ids.service.AlertService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/ids")
@Tag(name = "IDS - Intrusion Detection System", description = "Query alerts, get statistics, update alert status")
public class IdsApiController {

    private final AlertService alertService;

    @Autowired
    public IdsApiController(AlertService alertService) { this.alertService = alertService; }

    @GetMapping("/alerts")
    @Operation(summary = "Get recent alerts", description = "Returns latest N alerts. Default limit=50, max=500")
    public ResponseEntity<List<Alert>> alerts(@RequestParam(value="limit", defaultValue="50") int limit) {
        return ResponseEntity.ok(alertService.getRecentAlerts(Math.min(limit, 500)));
    }

    @GetMapping("/alerts/open")
    @Operation(summary = "Get all open (unresolved) alerts")
    public ResponseEntity<List<Alert>> open() {
        return ResponseEntity.ok(alertService.getOpenAlerts());
    }

    @GetMapping("/alerts/ip/{ip}")
    @Operation(summary = "Get all alerts for a specific IP address")
    public ResponseEntity<List<Alert>> byIp(@PathVariable("ip") String ip) {
        return ResponseEntity.ok(alertService.getAlertsByIp(ip));
    }

    @GetMapping("/alerts/{id}")
    @Operation(summary = "Get a single alert by ID")
    public ResponseEntity<?> getById(@PathVariable("id") Long id) {
        return alertService.findById(id)
                .<ResponseEntity<?>>map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/stats")
    @Operation(summary = "Alert statistics", description = "Total today, by severity, and type breakdown")
    public ResponseEntity<Map<String,Object>> stats() {
        return ResponseEntity.ok(Map.of(
            "alertsToday",   alertService.countAlertsToday(),
            "criticalCount", alertService.countBySeverity(Alert.Severity.CRITICAL),
            "highCount",     alertService.countBySeverity(Alert.Severity.HIGH),
            "mediumCount",   alertService.countBySeverity(Alert.Severity.MEDIUM),
            "lowCount",      alertService.countBySeverity(Alert.Severity.LOW),
            "typeBreakdown", alertService.getAlertCountsByType()
        ));
    }

    @PostMapping("/alerts/{id}/status")
    @Operation(summary = "Update alert status",
               description = "Status values: OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE")
    public ResponseEntity<Alert> updateStatus(@PathVariable("id") Long id,
                                              @RequestParam("status") String status,
                                              @RequestParam(value="notes", required=false, defaultValue="") String notes) {
        return ResponseEntity.ok(alertService.updateStatus(id, Alert.AlertStatus.valueOf(status), notes));
    }

    @PostMapping("/fire-test-alert")
    @Operation(summary = "Fire a test alert (for testing)", description = "Fires a LOW severity test alert from 127.0.0.1")
    public ResponseEntity<Alert> fireTestAlert() {
        Alert a = alertService.fireAlert("127.0.0.1", "TEST_ALERT",
                "Manual test alert fired via Swagger", "SWAGGER_TEST", "LOW");
        return ResponseEntity.ok(a);
    }

    @PostMapping("/report-traffic")
    @Operation(summary = "Report traffic from external app", description = "Used by JSP integration filter")
    public ResponseEntity<Map<String,Object>> reportTraffic(@RequestBody Map<String,String> p) {
        return ResponseEntity.ok(Map.of("received", true, "ip", p.getOrDefault("ip","unknown")));
    }
}
