package com.cybersec.shared.phishing;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/phishing")
public class PhishingApiController {

    @Autowired
    private PhishingService phishingService;

    @GetMapping("/campaigns")
    public List<Map<String, Object>> getCampaigns() {
        return phishingService.getAllCampaigns();
    }

    @PostMapping("/campaigns")
    public String createCampaign(@RequestBody Map<String, String> request) {
        return phishingService.createCampaign(
            request.get("name"),
            request.get("target"),
            request.get("template")
        );
    }

    @PostMapping("/click/{id}")
    public void trackClick(@PathVariable String id) {
        phishingService.registerClick(id);
    }
}
