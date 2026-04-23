package com.cybersec.ransomware.controller;

import com.cybersec.ransomware.model.RansomwareAlert;
import com.cybersec.ransomware.model.RansomwareAlertRepository;
import com.cybersec.ransomware.service.RansomwareSimulatorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/ransomware")
public class RansomwareApiController {

    @Autowired
    private RansomwareSimulatorService simulatorService;

    @Autowired
    private RansomwareAlertRepository alertRepository;

    @PostMapping("/simulate")
    public Map<String, Object> simulate(@RequestBody Map<String, Double> features) {
        return simulatorService.simulateTraffic(
            features.getOrDefault("packetVar", 0.0),
            features.getOrDefault("entropy", 0.0),
            features.getOrDefault("fileAccess", 0.0),
            features.getOrDefault("duration", 0.0),
            features.getOrDefault("freq", 0.0)
        );
    }

    @PostMapping("/adversarial")
    public Map<String, Object> adversarial(@RequestBody Map<String, Double> features) {
        return simulatorService.generateAdversarialPayload(
            features.getOrDefault("packetVar", 0.0),
            features.getOrDefault("entropy", 0.0),
            features.getOrDefault("fileAccess", 0.0),
            features.getOrDefault("duration", 0.0),
            features.getOrDefault("freq", 0.0)
        );
    }

    @GetMapping("/alerts")
    public List<RansomwareAlert> getAlerts() {
        return alertRepository.findTop10ByOrderByTimestampDesc();
    }
    
    @GetMapping("/stats")
    public Map<String, Object> getStats() {
        long total = alertRepository.count();
        return Map.of(
            "totalDetections", total,
            "systemStatus", "PROTECTED",
            "activeShield", true
        );
    }
}
