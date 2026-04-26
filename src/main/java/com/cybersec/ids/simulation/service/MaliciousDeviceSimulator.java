package com.cybersec.ids.simulation.service;

import com.cybersec.ids.service.AlertService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class MaliciousDeviceSimulator {
    private static final Logger log = LoggerFactory.getLogger(MaliciousDeviceSimulator.class);
    
    private final AlertService alertService;
    private final AtomicBoolean active = new AtomicBoolean(false);
    private final AtomicLong bandwidthUsage = new AtomicLong(0); // in bytes/sec
    private String deviceIp = "192.168.1.200";

    @Autowired
    public MaliciousDeviceSimulator(AlertService alertService) {
        this.alertService = alertService;
    }

    public boolean isActive() { return active.get(); }
    public long getBandwidthUsage() { return bandwidthUsage.get(); }

    public void stop() {
        active.set(false);
        bandwidthUsage.set(0);
        log.info("Malicious Device Simulator STOPPED.");
    }

    @Async
    public void startMaliciousActivity() {
        if (active.getAndSet(true)) return;
        
        log.info("Malicious Device Simulator STARTED for IP: {}", deviceIp);
        
        // Simulate high bandwidth consumption and malicious activity
        new Thread(() -> {
            while (active.get()) {
                try {
                    // Simulate high bandwidth (between 50MB and 100MB per second)
                    long currentLoad = 50_000_000 + (long)(Math.random() * 50_000_000);
                    bandwidthUsage.set(currentLoad);
                    
                    // Periodically fire alerts based on activity
                    if (Math.random() > 0.7) {
                        alertService.fireAlert(deviceIp, "HIGH_BANDWIDTH_ANOMALY", 
                                "Device consuming excessive bandwidth: " + (currentLoad / 1024 / 1024) + " MB/s", 
                                "NETWORK_MONITOR", "HIGH");
                    }
                    
                    if (Math.random() > 0.8) {
                        alertService.fireAlert(deviceIp, "SUSPICIOUS_OUTBOUND_TRAFFIC", 
                                "Malicious device attempting to connect to C2 server", 
                                "TRAFFIC_ANALYZER", "CRITICAL");
                    }

                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }).start();
    }

    public void setDeviceIp(String ip) {
        this.deviceIp = ip;
    }
}
