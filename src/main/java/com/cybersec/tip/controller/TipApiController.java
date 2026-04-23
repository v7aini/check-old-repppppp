package com.cybersec.tip.controller;
import com.cybersec.tip.model.IocIndicator;
import com.cybersec.tip.repository.IocIndicatorRepository;
import com.cybersec.tip.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController
@RequestMapping("/api/tip")
public class TipApiController {
    private final IocIndicatorRepository iocRepo;
    private final ThreatScoringService scoring;
    private final CveLookupService cve;
    private final FeedAggregatorService feed;

    @Autowired
    public TipApiController(IocIndicatorRepository r, ThreatScoringService s, CveLookupService c, FeedAggregatorService f) {
        this.iocRepo=r; this.scoring=s; this.cve=c; this.feed=f;
    }

    @GetMapping("/ioc/check")
    public ResponseEntity<Map<String,Object>> check(@RequestParam("value") String value) {
        int score = value.matches("\\d+\\.\\d+\\.\\d+\\.\\d+") ? scoring.scoreIp(value) : scoring.scoreDomain(value);
        return ResponseEntity.ok(Map.of("indicator",value,"score",score,"level",ThreatScoringService.getThreatLevel(score),"found",scoring.lookupIndicator(value).isPresent()));
    }
    @GetMapping("/ioc/top")
    public ResponseEntity<List<IocIndicator>> top(@RequestParam(value="limit", defaultValue="20") int limit) {
        return ResponseEntity.ok(iocRepo.findTopThreatsByScore(Math.min(limit,100)));
    }
    @PostMapping("/ioc")
    public ResponseEntity<IocIndicator> add(@RequestBody IocIndicator i) {
        i.setStatus(IocIndicator.IocStatus.ACTIVE); return ResponseEntity.ok(iocRepo.save(i));
    }
    @GetMapping("/cve/{cveId}")
    public ResponseEntity<Map<String,Object>> getCve(@PathVariable("cveId") String cveId) { return ResponseEntity.ok(cve.lookupCve(cveId)); }
    @GetMapping("/cve/search")
    public ResponseEntity<List<Map<String,Object>>> searchCve(@RequestParam("keyword") String keyword, @RequestParam(value="limit", defaultValue="10") int limit) {
        return ResponseEntity.ok(cve.searchCves(keyword, limit));
    }
    @GetMapping("/cve/recent-critical")
    public ResponseEntity<List<Map<String,Object>>> recentCritical() { return ResponseEntity.ok(cve.getRecentCriticalCves()); }
    @PostMapping("/feed/trigger")
    public ResponseEntity<Map<String,Object>> trigger() {
        return ResponseEntity.ok(Map.of("ingested",feed.triggerManualIngest(),"status","complete"));
    }
    @GetMapping("/feed/status")
    public ResponseEntity<Map<String,Object>> feedStatus() {
        return ResponseEntity.ok(Map.of("enabled",feed.isFeedEnabled(),"lastRun",feed.getLastRunTime()!=null?feed.getLastRunTime().toString():"never","lastCount",feed.getLastIngestCount(),"activeIocs",iocRepo.countByStatus(IocIndicator.IocStatus.ACTIVE)));
    }
}
