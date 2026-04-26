package com.cybersec.ids.controller;

import com.cybersec.ids.service.AnalyticsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/analytics")
public class AnalyticsController {

    private final AnalyticsService analyticsService;

    @Autowired
    public AnalyticsController(AnalyticsService analyticsService) {
        this.analyticsService = analyticsService;
    }

    @GetMapping("/trends")
    public ResponseEntity<Map<String, Object>> getTrends(@RequestParam(value = "days", defaultValue = "7") int days) {
        return ResponseEntity.ok(analyticsService.getTrendData(days));
    }

    @GetMapping("/distribution")
    public ResponseEntity<Map<String, Long>> getDistribution(@RequestParam(value = "days", defaultValue = "7") int days) {
        return ResponseEntity.ok(analyticsService.getAttackTypeDistribution(days));
    }
}
