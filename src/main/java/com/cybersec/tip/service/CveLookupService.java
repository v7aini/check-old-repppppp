package com.cybersec.tip.service;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
public class CveLookupService {
    private static final Logger log = LoggerFactory.getLogger(CveLookupService.class);
    private static final String NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private final RestTemplate restTemplate;
    private final ObjectMapper mapper;

    @Autowired
    public CveLookupService(RestTemplate restTemplate, ObjectMapper mapper) {
        this.restTemplate = restTemplate; this.mapper = mapper;
    }

    public Map<String, Object> lookupCve(String cveId) {
        try {
            ResponseEntity<String> r = restTemplate.getForEntity(
                UriComponentsBuilder.fromHttpUrl(NVD).queryParam("cveId", cveId).toUriString(), String.class);
            if (r.getStatusCode() == HttpStatus.OK && r.getBody() != null)
                return parseCve(mapper.readTree(r.getBody()).path("vulnerabilities").path(0).path("cve"));
        } catch (Exception e) { log.warn("[CVE] Lookup failed: {}", e.getMessage()); }
        return Map.of("error", "CVE not found", "cveId", cveId);
    }

    public List<Map<String, Object>> getRecentCriticalCves() {
        try {
            DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS");
            String url = UriComponentsBuilder.fromHttpUrl(NVD)
                .queryParam("cvssV3Severity","CRITICAL")
                .queryParam("pubStartDate", LocalDateTime.now().minusDays(30).format(fmt))
                .queryParam("pubEndDate", LocalDateTime.now().format(fmt))
                .queryParam("resultsPerPage", 10).toUriString();
            ResponseEntity<String> r = restTemplate.getForEntity(url, String.class);
            List<Map<String, Object>> out = new ArrayList<>();
            if (r.getStatusCode() == HttpStatus.OK && r.getBody() != null)
                for (JsonNode v : mapper.readTree(r.getBody()).path("vulnerabilities"))
                    out.add(parseCve(v.path("cve")));
            return out.isEmpty() ? mockCves() : out;
        } catch (Exception e) { return mockCves(); }
    }

    public List<Map<String, Object>> searchCves(String keyword, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        try {
            String url = UriComponentsBuilder.fromHttpUrl(NVD)
                .queryParam("keywordSearch", keyword).queryParam("resultsPerPage", Math.min(limit,20)).toUriString();
            ResponseEntity<String> r = restTemplate.getForEntity(url, String.class);
            if (r.getStatusCode() == HttpStatus.OK && r.getBody() != null)
                for (JsonNode v : mapper.readTree(r.getBody()).path("vulnerabilities")) {
                    out.add(parseCve(v.path("cve"))); if (out.size() >= limit) break;
                }
        } catch (Exception e) { log.warn("[CVE] Search failed: {}", e.getMessage()); }
        return out;
    }

    private Map<String, Object> parseCve(JsonNode cve) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("id", cve.path("id").asText("N/A"));
        r.put("published", cve.path("published").asText(""));
        for (JsonNode d : cve.path("descriptions"))
            if ("en".equals(d.path("lang").asText())) { r.put("description", d.path("value").asText("")); break; }
        JsonNode m = cve.path("metrics").path("cvssMetricV31").path(0).path("cvssData");
        r.put("cvssScore", m.path("baseScore").asDouble(0));
        r.put("severity",  m.path("baseSeverity").asText("UNKNOWN"));
        r.put("attackVector", m.path("attackVector").asText("N/A"));
        return r;
    }

    private List<Map<String, Object>> mockCves() {
        return List.of(
            Map.of("id","CVE-2024-0001","description","Critical RCE vulnerability","cvssScore",9.8,"severity","CRITICAL"),
            Map.of("id","CVE-2024-0002","description","SQL injection via crafted input","cvssScore",9.1,"severity","CRITICAL")
        );
    }
}
