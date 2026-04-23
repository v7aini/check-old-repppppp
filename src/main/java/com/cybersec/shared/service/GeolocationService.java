package com.cybersec.shared.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class GeolocationService {
    private static final Logger log = LoggerFactory.getLogger(GeolocationService.class);
    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper mapper = new ObjectMapper();

    public Map<String, Object> getGeoData(String ip) {
        Map<String, Object> result = new HashMap<>();
        if (ip.equals("127.0.0.1") || ip.startsWith("192.168.") || ip.startsWith("10.")) {
            result.put("country", "Local Network");
            result.put("lat", 0.0);
            result.put("lon", 0.0);
            return result;
        }

        try {
            String url = "http://ip-api.com/json/" + ip;
            String response = restTemplate.getForObject(url, String.class);
            JsonNode node = mapper.readTree(response);
            
            if ("success".equals(node.get("status").asText())) {
                result.put("country", node.get("country").asText());
                result.put("lat", node.get("lat").asDouble());
                result.put("lon", node.get("lon").asDouble());
            }
        } catch (Exception e) {
            log.error("Geo lookup failed for {}: {}", ip, e.getMessage());
            result.put("country", "Unknown");
            result.put("lat", 0.0);
            result.put("lon", 0.0);
        }
        return result;
    }
}
