package com.cybersec.ids.simulation.controller;

import com.cybersec.ids.service.DetectionModelService;
import com.cybersec.ids.simulation.service.IdsSimulationService;
import com.cybersec.ids.simulation.service.MaliciousDeviceSimulator;
import com.cybersec.ids.simulation.service.VirtualAttackerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.List;

@RestController
@RequestMapping("/api/simulation")
@Tag(name = "Attack Simulation", description = "Launch virtual attackers, fire real attack payloads through the detection pipeline")
public class IdsSimulationController {

    private final IdsSimulationService idsSimulationService;
    private final MaliciousDeviceSimulator maliciousDeviceSimulator;
    private final DetectionModelService detectionModelService;
    private final VirtualAttackerService virtualAttacker;

    @Autowired
    public IdsSimulationController(IdsSimulationService idsSimulationService, 
                                 MaliciousDeviceSimulator maliciousDeviceSimulator,
                                 DetectionModelService detectionModelService,
                                 VirtualAttackerService virtualAttacker) {
        this.idsSimulationService = idsSimulationService;
        this.maliciousDeviceSimulator = maliciousDeviceSimulator;
        this.detectionModelService = detectionModelService;
        this.virtualAttacker = virtualAttacker;
    }

    // =============== EXISTING SIMULATION CONTROLS ===============

    @PostMapping("/ids/start")
    @Operation(summary = "Start IDS alert simulation")
    public ResponseEntity<Map<String, String>> startIds() {
        idsSimulationService.startSimulation();
        return ResponseEntity.ok(Map.of("status", "started"));
    }

    @PostMapping("/ids/stop")
    @Operation(summary = "Stop IDS alert simulation")
    public ResponseEntity<Map<String, String>> stopIds() {
        idsSimulationService.stopSimulation();
        return ResponseEntity.ok(Map.of("status", "stopped"));
    }

    @PostMapping("/device/start")
    @Operation(summary = "Start malicious device bandwidth simulation")
    public ResponseEntity<Map<String, String>> startDevice() {
        maliciousDeviceSimulator.startMaliciousActivity();
        return ResponseEntity.ok(Map.of("status", "started"));
    }

    @PostMapping("/device/stop")
    @Operation(summary = "Stop malicious device simulation")
    public ResponseEntity<Map<String, String>> stopDevice() {
        maliciousDeviceSimulator.stop();
        return ResponseEntity.ok(Map.of("status", "stopped"));
    }

    @PostMapping("/ml/toggle")
    @Operation(summary = "Toggle ML auto-blocking")
    public ResponseEntity<Map<String, Object>> toggleMl(@RequestParam("enabled") boolean enabled) {
        detectionModelService.setTrainingEnabled(enabled);
        return ResponseEntity.ok(Map.of("enabled", detectionModelService.isTrainingEnabled()));
    }

    @GetMapping("/status")
    @Operation(summary = "Get all simulation statuses")
    public ResponseEntity<Map<String, Object>> getStatus() {
        return ResponseEntity.ok(Map.of(
            "idsRunning", idsSimulationService.isRunning(),
            "deviceRunning", maliciousDeviceSimulator.isActive(),
            "mlEnabled", detectionModelService.isTrainingEnabled(),
            "deviceBandwidth", maliciousDeviceSimulator.getBandwidthUsage(),
            "attackerActive", virtualAttacker.isActive(),
            "attackerIp", virtualAttacker.getAttackerIp(),
            "attackerName", virtualAttacker.getAttackerName()
        ));
    }

    // =============== VIRTUAL ATTACKER CONTROLS ===============

    @PostMapping("/attacker/start")
    @Operation(summary = "⚔️ Launch Virtual Attacker (continuous)",
               description = "Starts continuous attack waves from a virtual IP. Attacks go through the full WAF/IDS/AI pipeline. Fires SQLi, XSS, brute-force, DDoS, Log4Shell, and more.")
    public ResponseEntity<Map<String, Object>> startAttacker(
            @RequestParam(name = "ip", defaultValue = "10.66.6.100") String ip,
            @RequestParam(name = "name", defaultValue = "Virtual Attacker") String name,
            @RequestParam(name = "intervalMs", defaultValue = "3000") int intervalMs) {
        virtualAttacker.setAttackerIp(ip);
        virtualAttacker.setAttackerName(name);
        virtualAttacker.setAttackInterval(intervalMs);
        virtualAttacker.startAttack();
        return ResponseEntity.ok(Map.of(
            "status", "launched",
            "attackerIp", ip,
            "attackerName", name,
            "intervalMs", intervalMs,
            "message", "Virtual attacker is now sending real attack payloads through the detection pipeline!"
        ));
    }

    @PostMapping("/attacker/stop")
    @Operation(summary = "Stop Virtual Attacker")
    public ResponseEntity<Map<String, String>> stopAttacker() {
        virtualAttacker.stop();
        return ResponseEntity.ok(Map.of("status", "stopped"));
    }

    @PostMapping("/attacker/fire")
    @Operation(summary = "🎯 Fire a single attack type",
               description = "Fire one attack of a specific type. Types: SQL_INJECTION, XSS, BRUTE_FORCE, PATH_TRAVERSAL, COMMAND_INJECTION, DDOS_FLOOD, LOG4SHELL, UNAUTHORIZED_API")
    public ResponseEntity<Map<String, Object>> fireSingleAttack(
            @RequestParam("type") String type,
            @RequestParam(name = "ip", defaultValue = "10.66.6.100") String ip) {
        virtualAttacker.setAttackerIp(ip);
        return ResponseEntity.ok(virtualAttacker.fireManualAttack(type));
    }

    @PostMapping("/attacker/custom")
    @Operation(summary = "🔧 Fire a custom attack payload",
               description = "Send any custom payload through the AI classifier from the attacker IP. Test any URI + payload combination.")
    public ResponseEntity<Map<String, Object>> fireCustomAttack(
            @RequestParam("uri") String uri,
            @RequestParam("payload") String payload,
            @RequestParam(name = "method", defaultValue = "GET") String method,
            @RequestParam(name = "ip", defaultValue = "10.66.6.100") String ip) {
        virtualAttacker.setAttackerIp(ip);
        return ResponseEntity.ok(virtualAttacker.fireCustomAttack(uri, payload, method));
    }

    @GetMapping("/attacker/attacks")
    @Operation(summary = "List available attack types", description = "Returns all pre-built attack types with sample URIs and descriptions")
    public ResponseEntity<List<Map<String, String>>> availableAttacks() {
        return ResponseEntity.ok(virtualAttacker.getAvailableAttacks());
    }

    @GetMapping("/attacker/log")
    @Operation(summary = "View attack log", description = "Returns the last 50 attacks fired by the virtual attacker with classification results")
    public ResponseEntity<List<Map<String, Object>>> attackLog() {
        return ResponseEntity.ok(virtualAttacker.getAttackLog());
    }
}
