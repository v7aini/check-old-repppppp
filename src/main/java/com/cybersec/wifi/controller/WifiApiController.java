package com.cybersec.wifi.controller;

import com.cybersec.wifi.model.WifiNetwork;
import com.cybersec.wifi.service.WifiService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/wifi")
@Tag(name = "Wi-Fi Analysis", description = "Realtime Wi-Fi signal analysis and AP scanning")
public class WifiApiController {

    private final WifiService wifiService;

    @Autowired
    public WifiApiController(WifiService wifiService) {
        this.wifiService = wifiService;
    }

    @GetMapping("/scan")
    @Operation(summary = "Scan for nearby access points")
    public ResponseEntity<List<WifiNetwork>> scan() {
        return ResponseEntity.ok(wifiService.scanNetworks());
    }

    @GetMapping("/stats")
    @Operation(summary = "Get frequency spectrum stats")
    public ResponseEntity<Map<String, Object>> stats() {
        Map<String, Object> response = new HashMap<>();
        response.put("spectrum", wifiService.getFrequencyStats());
        response.put("totalAPs", wifiService.scanNetworks().size());
        return ResponseEntity.ok(response);
    }
}
