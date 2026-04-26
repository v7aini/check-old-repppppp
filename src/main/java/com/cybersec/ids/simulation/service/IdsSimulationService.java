package com.cybersec.ids.simulation.service;

import com.cybersec.ids.service.AlertService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class IdsSimulationService {
    private static final Logger log = LoggerFactory.getLogger(IdsSimulationService.class);
    private final AlertService alertService;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Random random = new Random();

    @Autowired
    public IdsSimulationService(AlertService alertService) {
        this.alertService = alertService;
    }

    public boolean isRunning() {
        return running.get();
    }

    public void stopSimulation() {
        running.set(false);
        log.info("IDS Simulation STOPPED manually.");
    }

    @Async
    public void startSimulation() {
        if (running.getAndSet(true)) {
            log.warn("Simulation is already running.");
            return;
        }

        log.info("IDS Simulation STARTED.");
        String[] types = {"SQL_INJECTION", "XSS", "BRUTE_FORCE", "PORT_SCAN", "DDOS_ATTACK"};
        String[] ips = {"192.168.1.50", "10.0.0.15", "172.16.0.44", "45.12.88.2", "103.44.12.5"};

        while (running.get()) {
            try {
                Thread.sleep(3000 + random.nextInt(7000));
                if (!running.get()) break;

                String ip = ips[random.nextInt(ips.length)];
                String type = types[random.nextInt(types.length)];
                String sev = random.nextInt(10) > 7 ? "HIGH" : "MEDIUM";
                
                alertService.fireAlert(ip, type, "Simulated attack detected from " + ip, "IDS_SIMULATOR", sev);
                log.info("Simulated alert fired: {} from {}", type, ip);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
}
