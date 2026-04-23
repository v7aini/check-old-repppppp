package com.cybersec.ids.service;

import com.cybersec.shared.service.PythonMlClient;
import com.cybersec.waf.service.IpFirewallService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class DdosDetectionService {
    private static final Logger log = LoggerFactory.getLogger(DdosDetectionService.class);
    private final PythonMlClient mlClient;
    private final IpFirewallService firewallService;
    private final AlertService alertService;

    // IP -> Statistics over the last window
    private final Map<String, List<Long>> packetTimes = new ConcurrentHashMap<>();
    private final Map<String, Integer> synCounts = new ConcurrentHashMap<>();

    @Autowired
    public DdosDetectionService(PythonMlClient mlClient, 
                                IpFirewallService firewallService,
                                AlertService alertService) {
        this.mlClient = mlClient;
        this.firewallService = firewallService;
        this.alertService = alertService;
    }

    public void trackPacket(String ip, String type) {
        long now = System.currentTimeMillis();
        packetTimes.computeIfAbsent(ip, k -> Collections.synchronizedList(new ArrayList<>())).add(now);
        if ("SYN".equalsIgnoreCase(type)) {
            synCounts.merge(ip, 1, Integer::sum);
        }
    }

    @Scheduled(fixedDelay = 10000) // Every 10 seconds
    public void analyzeTraffic() {
        long windowStart = System.currentTimeMillis() - 10000;
        
        for (String ip : packetTimes.keySet()) {
            List<Long> times = packetTimes.get(ip);
            times.removeIf(t -> t < windowStart);
            
            if (times.size() > 50) { // Threshold for ML analysis
                List<Integer> features = new ArrayList<>(Collections.nCopies(20, 0));
                features.set(0, times.size()); // packet rate
                features.set(1, synCounts.getOrDefault(ip, 0)); // syn rate
                // ... fill other simulated features
                
                Map<String, Object> result = mlClient.detectDdos(features);
                String classification = (String) result.get("classification");
                
                if (!"NORMAL".equals(classification)) {
                    log.warn("[DDOS] {} detected from {} (Confidence: {})", classification, ip, result.get("confidence"));
                    
                    alertService.fireAlert(ip, "DDOS_ATTACK", 
                        String.format("DDoS [%s] detected by CNN model (CIC-DDoS2019). Confidence: %.2f", 
                        classification, result.get("confidence")), 
                        "CNN_DDOS_DETECTOR", "CRITICAL");
                    
                    // AUTO RATE LIMITING / BLOCKING
                    firewallService.blockIp(ip, "DDoS Auto-Mitigation: " + classification, null);
                }
            }
            
            // Cleanup
            if (times.isEmpty()) {
                packetTimes.remove(ip);
                synCounts.remove(ip);
            } else {
                synCounts.put(ip, 0); // Reset syn count for next window
            }
        }
    }
}
