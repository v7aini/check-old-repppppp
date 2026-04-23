package com.cybersec.tip.service;
import com.cybersec.tip.model.IocIndicator;
import com.cybersec.tip.model.IocIndicator.IocStatus;
import com.cybersec.tip.model.IocIndicator.IocType;
import com.cybersec.tip.repository.IocIndicatorRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.time.LocalDateTime;
import java.util.List;

@Service
public class FeedAggregatorService {
    private static final Logger log = LoggerFactory.getLogger(FeedAggregatorService.class);
    private final IocIndicatorRepository repo;
    private final ObjectMapper mapper;
    private final RestTemplate restTemplate;
    @Value("${tip.otx.api-key:}") private String otxApiKey;
    @Value("${tip.otx.base-url:https://otx.alienvault.com/api/v1}") private String otxBase;
    @Value("${tip.feed.enabled:true}") private boolean feedEnabled;
    private int lastCount = 0;
    private LocalDateTime lastRun;

    @Autowired
    public FeedAggregatorService(IocIndicatorRepository repo, ObjectMapper mapper, RestTemplate restTemplate) {
        this.repo = repo; this.mapper = mapper; this.restTemplate = restTemplate;
    }

    @Scheduled(cron = "0 0 * * * *")
    public void ingestFeeds() {
        if (!feedEnabled) return;
        lastRun = LocalDateTime.now();
        lastCount = (otxApiKey != null && !otxApiKey.isBlank() && !otxApiKey.equals("YOUR_OTX_API_KEY_HERE"))
                    ? ingestOtx() : ingestMock();
        log.info("[TIP] Ingested {} indicators", lastCount);
    }

    private int ingestOtx() {
        int saved = 0;
        try {
            HttpHeaders h = new HttpHeaders(); h.set("X-OTX-API-KEY", otxApiKey);
            ResponseEntity<String> resp = restTemplate.exchange(otxBase + "/pulses/subscribed?limit=50",
                    HttpMethod.GET, new HttpEntity<>(h), String.class);
            if (resp.getStatusCode() == HttpStatus.OK && resp.getBody() != null) {
                for (JsonNode pulse : mapper.readTree(resp.getBody()).path("results")) {
                    String feed = "OTX:" + pulse.path("name").asText("?");
                    for (JsonNode ind : pulse.path("indicators")) {
                        IocType t = mapType(ind.path("type").asText());
                        String val = ind.path("indicator").asText();
                        if (t == null || val.isBlank() || repo.existsByIndicatorValue(val)) continue;
                        repo.save(IocIndicator.builder().indicatorType(t).indicatorValue(val)
                                .threatScore(60).sourceFeed(feed).status(IocStatus.ACTIVE)
                                .firstSeen(LocalDateTime.now()).lastSeen(LocalDateTime.now()).build());
                        saved++;
                    }
                }
            }
        } catch (Exception e) { log.error("[TIP] OTX error: {}", e.getMessage()); }
        return saved;
    }

    private int ingestMock() {
        String[][] data = {
            {"IP","192.0.2.10","Known C2 server","90"},{"IP","198.51.100.5","Botnet node","85"},
            {"IP","203.0.113.42","Tor exit node","65"},{"IP","100.64.0.1","Brute-force source","75"},
            {"IP","100.64.0.2","SQL injection scanner","80"},{"DOMAIN","malware-c2.example.com","C2 domain","95"},
            {"URL","http://evil.example.com/payload.exe","Malware dropper","92"},
            {"FILE_HASH","d41d8cd98f00b204e9800998ecf8427e","Known ransomware","98"},
            {"IP","198.51.100.10","Port scanner","70"},{"IP","203.0.113.99","Credential stuffer","78"}
        };
        int saved = 0;
        for (String[] row : data) {
            if (repo.existsByIndicatorValue(row[1])) continue;
            try {
                IocType t = IocType.valueOf(row[0]);
                repo.save(IocIndicator.builder().indicatorType(t).indicatorValue(row[1])
                        .description(row[2]).threatScore(Integer.parseInt(row[3]))
                        .sourceFeed("Mock Feed").status(IocStatus.ACTIVE)
                        .firstSeen(LocalDateTime.now()).lastSeen(LocalDateTime.now()).build());
                saved++;
            } catch (Exception ignored) {}
        }
        return saved;
    }

    private IocType mapType(String t) {
        return switch (t.toLowerCase()) {
            case "ipv4","ipv6" -> IocType.IP;
            case "domain","hostname" -> IocType.DOMAIN;
            case "url" -> IocType.URL;
            case "filehash-md5","filehash-sha1","filehash-sha256" -> IocType.FILE_HASH;
            case "email" -> IocType.EMAIL;
            default -> null;
        };
    }

    public int getLastIngestCount() { return lastCount; }
    public LocalDateTime getLastRunTime() { return lastRun; }
    public boolean isFeedEnabled() { return feedEnabled; }
    public int triggerManualIngest() { ingestFeeds(); return lastCount; }
}
