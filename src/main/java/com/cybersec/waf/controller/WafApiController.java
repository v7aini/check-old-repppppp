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

@RestController
@RequestMapping("/api/waf")
@Tag(name = "WAF - Web Application Firewall", description = "View blocks, manage IP blocklist, check rate limits")
public class WafApiController {

    private final IpFirewallService firewall;
    private final RateLimiterService rateLimit;
    private final WafBlockRepository blockRepo;
    private final IpBlocklistRepository ipRepo;

    @Autowired
    public WafApiController(IpFirewallService fw, RateLimiterService rl,
                             WafBlockRepository br, IpBlocklistRepository ir) {
        this.firewall=fw; this.rateLimit=rl; this.blockRepo=br; this.ipRepo=ir;
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
}
