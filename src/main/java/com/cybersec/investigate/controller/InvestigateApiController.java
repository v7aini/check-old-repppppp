package com.cybersec.investigate.controller;

import com.cybersec.investigate.service.VulnerabilityScannerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/investigate")
@Tag(name = "Investigation Tool", description = "Vulnerability scanning and deep device analysis")
public class InvestigateApiController {

    private final VulnerabilityScannerService scannerService;

    @Autowired
    public InvestigateApiController(VulnerabilityScannerService scannerService) {
        this.scannerService = scannerService;
    }

    @GetMapping("/scan")
    @Operation(summary = "Perform a vulnerability scan on an IP")
    public ResponseEntity<Map<String, Object>> scan(@RequestParam("ip") String ip) {
        List<Integer> commonPorts = List.of(21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 8080);
        List<Integer> openPorts = scannerService.scanPorts(ip, commonPorts);
        
        Map<Integer, List<Map<String, String>>> vulnerabilities = new HashMap<>();
        for (int port : openPorts) {
            vulnerabilities.put(port, scannerService.checkVulnerabilities(port));
        }

        Map<String, Object> response = new HashMap<>();
        response.put("ip", ip);
        response.put("openPorts", openPorts);
        response.put("vulnerabilities", vulnerabilities);
        response.put("scanTime", new java.util.Date().toString());
        
        return ResponseEntity.ok(response);
    }
}
