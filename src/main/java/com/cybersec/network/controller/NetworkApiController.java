package com.cybersec.network.controller;

import com.cybersec.network.model.PacketRecord;
import com.cybersec.network.service.NetworkCaptureService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@RequestMapping("/api/network")
@Tag(name = "Network Capture", description = "Wireshark-style packet capture, ARP table, MAC address lookup")
public class NetworkApiController {

    private final NetworkCaptureService captureService;

    @Autowired
    public NetworkApiController(NetworkCaptureService captureService) {
        this.captureService = captureService;
    }

    @GetMapping("/packets")
    @Operation(summary = "Get recent captured packets (last 200)")
    public ResponseEntity<List<PacketRecord>> packets() {
        return ResponseEntity.ok(captureService.getRecentPackets());
    }

    @GetMapping("/packets/suspicious")
    @Operation(summary = "Get suspicious packets only")
    public ResponseEntity<List<PacketRecord>> suspicious() {
        return ResponseEntity.ok(captureService.getSuspiciousPackets());
    }

    @GetMapping("/stats")
    @Operation(summary = "Protocol statistics and top talkers")
    public ResponseEntity<Map<String, Object>> stats() {
        Map<String, Long> protocols = new LinkedHashMap<>();
        for (Object[] row : captureService.getProtocolStats())
            protocols.put((String) row[0], (Long) row[1]);

        Map<String, Long> talkers = new LinkedHashMap<>();
        for (Object[] row : captureService.getTopTalkers())
            talkers.put((String) row[0], (Long) row[1]);

        return ResponseEntity.ok(Map.of(
            "packetsToday", captureService.countPacketsToday(),
            "protocols",    protocols,
            "topTalkers",   talkers,
            "captureEnabled", captureService.isEnabled()
        ));
    }

    @GetMapping("/mac/{ip}")
    @Operation(summary = "Get MAC address for an IP via ARP lookup")
    public ResponseEntity<Map<String, String>> macLookup(@PathVariable("ip") String ip) {
        String mac = captureService.getMacAddress(ip);
        return ResponseEntity.ok(Map.of("ip", ip, "mac", mac));
    }

    @GetMapping("/arp")
    @Operation(summary = "Get full ARP table — all visible devices on the network")
    public ResponseEntity<List<Map<String, String>>> arpTable() {
        return ResponseEntity.ok(captureService.getArpTable());
    }

    @GetMapping("/interfaces")
    @Operation(summary = "List all network interfaces on this machine")
    public ResponseEntity<List<Map<String, String>>> interfaces() {
        return ResponseEntity.ok(captureService.getNetworkInterfaces());
    }

    @PostMapping("/capture/start")
    @Operation(summary = "Enable HTTP packet capture")
    public ResponseEntity<Map<String, Object>> startCapture() {
        captureService.setEnabled(true);
        return ResponseEntity.ok(Map.of("capturing", true, "message", "Packet capture enabled"));
    }

    @PostMapping("/capture/stop")
    @Operation(summary = "Disable HTTP packet capture")
    public ResponseEntity<Map<String, Object>> stopCapture() {
        captureService.setEnabled(false);
        return ResponseEntity.ok(Map.of("capturing", false, "message", "Packet capture disabled"));
    }
}
