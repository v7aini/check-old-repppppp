package com.cybersec.investigate.controller;

import com.cybersec.investigate.model.DeviceInvestigation;
import com.cybersec.investigate.service.InvestigationService;
import com.cybersec.network.service.NetworkCaptureService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@RequestMapping("/api/investigate")
@Tag(name = "Investigation Tool", description = "Investigate, block, monitor and profile devices by IP. Includes MAC address lookup.")
public class InvestigationApiController {

    private final InvestigationService investigationService;
    private final NetworkCaptureService networkService;

    @Autowired
    public InvestigationApiController(InvestigationService investigationService,
                                       NetworkCaptureService networkService) {
        this.investigationService = investigationService;
        this.networkService = networkService;
    }

    @GetMapping
    @Operation(summary = "List all device investigations")
    public ResponseEntity<List<DeviceInvestigation>> all() {
        return ResponseEntity.ok(investigationService.getAllInvestigations());
    }

    @PostMapping("/start")
    @Operation(summary = "Start investigating an IP address",
               description = "Resolves hostname, MAC address, counts existing alerts, creates investigation record.")
    public ResponseEntity<DeviceInvestigation> start(@RequestParam("ip") String ip,
                                                      @RequestParam(value = "reason", defaultValue = "Manual investigation") String reason) {
        return ResponseEntity.ok(investigationService.startInvestigation(ip, reason));
    }

    @PostMapping("/{id}/block")
    @Operation(summary = "Block a device — adds IP to WAF blocklist and sends Telegram notification")
    public ResponseEntity<DeviceInvestigation> block(@PathVariable("id") Long id,
                                                      @RequestParam(value = "reason", defaultValue = "Blocked via investigation tool") String reason) {
        return ResponseEntity.ok(investigationService.blockDevice(id, reason));
    }

    @PostMapping("/{id}/whitelist")
    @Operation(summary = "Whitelist a device — removes from WAF blocklist")
    public ResponseEntity<DeviceInvestigation> whitelist(@PathVariable("id") Long id) {
        return ResponseEntity.ok(investigationService.whitelistDevice(id));
    }

    @PostMapping("/{id}/resolve")
    @Operation(summary = "Resolve an investigation — mark as done")
    public ResponseEntity<DeviceInvestigation> resolve(@PathVariable("id") Long id,
                                                        @RequestParam(value = "notes", required = false) String notes) {
        return ResponseEntity.ok(investigationService.resolveInvestigation(id, notes));
    }

    @PostMapping("/{id}/refresh")
    @Operation(summary = "Refresh device data — re-resolve MAC and recount alerts")
    public ResponseEntity<DeviceInvestigation> refresh(@PathVariable("id") Long id) {
        return ResponseEntity.ok(investigationService.refreshDevice(id));
    }

    @GetMapping("/profile/{ip}")
    @Operation(summary = "Get complete device profile — alerts, packets, MAC, hostname")
    public ResponseEntity<Map<String, Object>> profile(@PathVariable("ip") String ip) {
        return ResponseEntity.ok(investigationService.getDeviceProfile(ip));
    }

    @GetMapping("/mac/{ip}")
    @Operation(summary = "Quick MAC address lookup for an IP")
    public ResponseEntity<Map<String, String>> mac(@PathVariable("ip") String ip) {
        return ResponseEntity.ok(Map.of(
            "ip",  ip,
            "mac", networkService.getMacAddress(ip)
        ));
    }

    @GetMapping("/arp-table")
    @Operation(summary = "Get all devices in ARP table — like running 'arp -a'")
    public ResponseEntity<List<Map<String, String>>> arpTable() {
        return ResponseEntity.ok(networkService.getArpTable());
    }
}
