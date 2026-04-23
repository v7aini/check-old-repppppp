package com.cybersec.shared.phishing;

import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class PhishingService {
    private final Map<String, Map<String, Object>> campaigns = new ConcurrentHashMap<>();
    
    public String createCampaign(String name, String targetGroup, String template) {
        String id = UUID.randomUUID().toString();
        Map<String, Object> campaign = new HashMap<>();
        campaign.put("id", id);
        campaign.put("name", name);
        campaign.put("targetGroup", targetGroup);
        campaign.put("template", template);
        campaign.put("sentAt", LocalDateTime.now());
        campaign.put("sentCount", (int)(Math.random() * 500) + 100);
        campaign.put("clickCount", 0);
        campaign.put("compromisedCount", 0);
        campaign.put("status", "ACTIVE");
        
        campaigns.put(id, campaign);
        return id;
    }

    public void registerClick(String campaignId) {
        if (campaigns.containsKey(campaignId)) {
            Map<String, Object> c = campaigns.get(campaignId);
            c.put("clickCount", (int)c.get("clickCount") + 1);
            if (Math.random() > 0.6) {
                c.put("compromisedCount", (int)c.get("compromisedCount") + 1);
            }
        }
    }

    public List<Map<String, Object>> getAllCampaigns() {
        return new ArrayList<>(campaigns.values());
    }
}
