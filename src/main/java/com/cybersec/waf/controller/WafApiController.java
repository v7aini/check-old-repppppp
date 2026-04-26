package com.cybersec.waf.controller;

import com.cybersec.waf.model.IpBlockEntry;
import com.cybersec.waf.repository.IpBlocklistRepository;
import com.cybersec.waf.repository.WafBlockRepository;
import com.cybersec.waf.service.IpFirewallService;
import com.cybersec.waf.service.RateLimiterService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;

import com.cybersec.ids.service.ThreatClassificationService;

import com.cybersec.ids.repository.AlertRepository;

@RestController
@RequestMapping("/api/waf")
@Tag(name = "WAF - Web Application Firewall", description = "View blocks, manage IP blocklist, check rate limits")
public class WafApiController {

    private final IpFirewallService firewall;
    private final RateLimiterService rateLimit;
    private final WafBlockRepository blockRepo;
    private final IpBlocklistRepository ipRepo;
    private final ThreatClassificationService threatService;
    private final AlertRepository alertRepo;

    @Autowired
    public WafApiController(IpFirewallService fw, RateLimiterService rl,
                             WafBlockRepository br, IpBlocklistRepository ir,
                             ThreatClassificationService ts, AlertRepository alertRepo) {
        this.firewall=fw; this.rateLimit=rl; this.blockRepo=br; this.ipRepo=ir; this.threatService=ts; this.alertRepo=alertRepo;
    }

    @GetMapping("/blocks/recent")
    @Operation(summary = "Get last 100 WAF blocks", description = "Returns recent blocked requests sorted by time desc")
    public ResponseEntity<?> recent() {
        return ResponseEntity.ok(blockRepo.findTop100ByOrderByBlockedAtDesc());
    }

    @GetMapping("/blocks/stats")
    @Operation(summary = "Block statistics by attack type (last 24h)")
    public ResponseEntity<Map<String,Object>> stats() {
        LocalDateTime since = LocalDateTime.now().minusHours(24);
        Map<String,Long> byType = new LinkedHashMap<>();
        blockRepo.countByTypeSince(since).forEach(r -> byType.put((String)r[0],(Long)r[1]));
        return ResponseEntity.ok(Map.of(
            "total24h", blockRepo.countByBlockedAtAfter(since),
            "byType", byType
        ));
    }

    @GetMapping("/blocklist")
    @Operation(summary = "Get all blocked IPs", description = "Returns active IP blocklist entries")
    public ResponseEntity<List<IpBlockEntry>> blocklist() {
        return ResponseEntity.ok(ipRepo.findByActiveTrue());
    }

    @PostMapping("/block-ip")
    @Operation(summary = "Block an IP address", description = "Adds an IP to the WAF blocklist. Param: ip=1.2.3.4, reason=spam")
    public ResponseEntity<Map<String,Object>> block(@RequestParam String ip,
                                                     @RequestParam(defaultValue="Manual block via API") String reason) {
        firewall.blockIp(ip, reason, null);
        return ResponseEntity.ok(Map.of("blocked", true, "ip", ip, "reason", reason));
    }

    @DeleteMapping("/block-ip/{ip}")
    @Operation(summary = "Unblock an IP address", description = "Removes IP from the WAF blocklist")
    public ResponseEntity<Map<String,Object>> unblock(@PathVariable("ip") String ip) {
        firewall.unblockIp(ip);
        return ResponseEntity.ok(Map.of("unblocked", true, "ip", ip));
    }

    @GetMapping("/rate-limit/{ip}")
    @Operation(summary = "Rate limit status for an IP", description = "Shows remaining tokens and strike count")
    public ResponseEntity<Map<String,Object>> rateLimitStatus(@PathVariable("ip") String ip) {
        return ResponseEntity.ok(Map.of(
            "ip",              ip,
            "remainingTokens", rateLimit.getRemainingTokens(ip),
            "strikes",         rateLimit.getStrikeCount(ip),
            "limitPerMinute",  100
        ));
    }

    @PostMapping("/rate-limit/{ip}/clear")
    @Operation(summary = "Clear rate limit strikes for an IP")
    public ResponseEntity<Map<String,Object>> clearStrikes(@PathVariable("ip") String ip) {
        rateLimit.clearStrikes(ip);
        return ResponseEntity.ok(Map.of("cleared", true, "ip", ip));
    }

    @PostMapping("/block-me")
    @Operation(summary = "🔒 Block MY IP (testing)",
               description = "Blocks your current IP so you can test the WAF block screen.")
    public ResponseEntity<Map<String,Object>> blockMe(jakarta.servlet.http.HttpServletRequest request) {
        String myIp = extractIp(request);
        firewall.blockIp(myIp, "Manual self-block for testing", LocalDateTime.now().plusHours(1));
        return ResponseEntity.ok(Map.of(
            "blocked", true,
            "ip", myIp,
            "message", "Your IP has been blocked! Load any non-whitelisted page to see WAF."
        ));
    }

    @PostMapping("/unblock-me")
    @Operation(summary = "🚨 Unblock MY IP (auto-detect)",
               description = "Detects your current IP from the request and removes it from the WAF blocklist + clears rate-limit strikes. Use this if you accidentally blocked yourself!")
    public ResponseEntity<Map<String,Object>> unblockMe(jakarta.servlet.http.HttpServletRequest request) {
        String myIp = extractIp(request);
        firewall.unblockIp(myIp);
        rateLimit.clearStrikes(myIp);
        threatService.clearFailedLogins(myIp);
        alertRepo.deleteBySourceIp(myIp);
        return ResponseEntity.ok(Map.of(
            "unblocked", true,
            "ip", myIp,
            "message", "Your IP has been unblocked and rate-limit strikes cleared!"
        ));
    }

    @PostMapping("/unblock-ip")
    @Operation(summary = "Unblock a specific IP (POST-based)",
               description = "Use this instead of DELETE if the dotted IP in the URL path causes issues. Param: ip=192.168.1.3")
    public ResponseEntity<Map<String,Object>> unblockByPost(@RequestParam("ip") String ip) {
        firewall.unblockIp(ip);
        rateLimit.clearStrikes(ip);
        threatService.clearFailedLogins(ip);
        alertRepo.deleteBySourceIp(ip);
        return ResponseEntity.ok(Map.of("unblocked", true, "ip", ip, "rateLimitCleared", true));
    }

    @PostMapping("/unblock-all")
    @Operation(summary = "⚠️ Unblock ALL IPs", description = "Deactivates every entry in the blocklist. Use with caution!")
    public ResponseEntity<Map<String,Object>> unblockAll() {
        List<IpBlockEntry> active = ipRepo.findByActiveTrue();
        active.forEach(e -> { e.setActive(false); ipRepo.save(e); });
        return ResponseEntity.ok(Map.of("unblocked", true, "count", active.size()));
    }

    private String extractIp(jakarta.servlet.http.HttpServletRequest r) {
        String xff = r.getHeader("X-Forwarded-For");
        return (xff != null && !xff.isBlank()) ? xff.split(",")[0].trim() : r.getRemoteAddr();
    }
}
