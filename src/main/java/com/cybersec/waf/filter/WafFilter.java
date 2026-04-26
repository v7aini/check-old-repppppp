package com.cybersec.waf.filter;
import com.cybersec.ids.service.AlertService;
import com.cybersec.waf.model.WafBlock;
import com.cybersec.waf.service.IpFirewallService;
import com.cybersec.waf.service.RateLimiterService;
import com.cybersec.waf.service.WafRuleService;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;

@Component
@Order(-200)
public class WafFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(WafFilter.class);
    private final IpFirewallService firewall;
    private final RateLimiterService rateLimit;
    private final WafRuleService ruleService;
    private final AlertService alertService;
    @Value("${waf.enabled:true}") private boolean enabled;

    @Autowired
    public WafFilter(IpFirewallService firewall,
                     RateLimiterService rateLimit,
                     WafRuleService ruleService,
                     @Lazy AlertService alertService) {  // @Lazy breaks wafFilter->alertService->WebSocket->webConfig->idsInterceptor->signatureEngine->alertService
        this.firewall = firewall; this.rateLimit = rateLimit;
        this.ruleService = ruleService; this.alertService = alertService;
    }

    private static final List<Pattern> SQLI = List.of(
        Pattern.compile("(?i)(union\\s+select|insert\\s+into|drop\\s+table|truncate\\s+table)"),
        Pattern.compile("(?i)(or\\s+1\\s*=\\s*1|and\\s+1\\s*=\\s*1)"),
        Pattern.compile("--\\s*$|;\\s*--"),
        Pattern.compile("(?i)(sleep|benchmark)\\s*\\("),
        Pattern.compile("(?i)(exec|execute)\\s*\\(")
    );
    private static final List<Pattern> XSS = List.of(
        Pattern.compile("(?i)<script[^>]*>"),
        Pattern.compile("(?i)on(error|load|click|mouseover)\\s*="),
        Pattern.compile("(?i)javascript\\s*:"),
        Pattern.compile("(?i)<(iframe|frame|embed|object)")
    );
    private static final List<Pattern> LFI = List.of(
        Pattern.compile("\\.\\./|\\.\\\\"),
        Pattern.compile("(?i)/etc/(passwd|shadow|hosts)"),
        Pattern.compile("(?i)%2e%2e%2f")
    );
    private static final List<Pattern> CMD = List.of(
        Pattern.compile("(?i)(;|\\|\\||&&)\\s*(ls|cat|id|whoami|bash|sh)"),
        Pattern.compile("(?i)`[^`]+`")
    );
    private static final List<Pattern> SCANNER = List.of(
        Pattern.compile("(?i)(sqlmap|nikto|masscan|nmap|burpsuite|w3af)")
    );

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        if (!enabled || isPublic(req.getRequestURI())) { chain.doFilter(req, res); return; }
        String ip  = ip(req);
        if ("0:0:0:0:0:0:0:1".equals(ip) || "127.0.0.1".equals(ip)) { chain.doFilter(req, res); return; } // Never block localhost
        String ua  = req.getHeader("User-Agent");
        String rawTgt = req.getRequestURI() + "?" + (req.getQueryString() != null ? req.getQueryString() : "");
        String tgt;
        try { tgt = java.net.URLDecoder.decode(rawTgt, java.nio.charset.StandardCharsets.UTF_8); }
        catch (Exception e) { tgt = rawTgt; }

        if (firewall.isBlocked(ip))             { block(res,req,ip,"IP_BLOCKED","IP blocklisted",403); return; }
        if (!rateLimit.isAllowed(ip))           { block(res,req,ip,"RATE_LIMIT","Too many requests",429); return; }
        if (ua != null && hit(ua, SCANNER))     { block(res,req,ip,"SCANNER","Scanner UA detected",403); return; }
        if (hit(tgt, SQLI))                     { block(res,req,ip,"SQL_INJECTION","SQLi: "+trim(tgt),403); return; }
        if (hit(tgt, XSS))                      { block(res,req,ip,"XSS","XSS: "+trim(tgt),403); return; }
        if (hit(tgt, LFI))                      { block(res,req,ip,"LFI","LFI: "+trim(tgt),403); return; }
        if (hit(tgt, CMD))                      { block(res,req,ip,"CMD_INJECTION","CMD: "+trim(tgt),403); return; }
        if (ruleService.matchCustomRules(tgt).isPresent()) { block(res,req,ip,"CUSTOM_RULE","Custom rule",403); return; }

        res.setHeader("X-Frame-Options","SAMEORIGIN");
        res.setHeader("X-Content-Type-Options","nosniff");
        res.setHeader("X-XSS-Protection","1; mode=block");
        res.setHeader("Strict-Transport-Security","max-age=31536000; includeSubDomains");
        chain.doFilter(req, res);
    }

    private void block(HttpServletResponse res, HttpServletRequest req, String ip,
                       String type, String detail, int status) throws IOException {
        log.warn("[WAF] {} | {} {}", type, req.getMethod(), req.getRequestURI());
        ruleService.saveBlock(WafBlock.builder().clientIp(ip).attackType(type).detail(detail)
                .requestUri(req.getRequestURI()).method(req.getMethod())
                .statusCode(status).blockedAt(LocalDateTime.now()).build());
        try { alertService.fireAlert(ip, type, detail, "WAF", "HIGH"); } catch (Exception ignored) {}
        res.setStatus(status); res.setContentType("application/json");
        res.getWriter().write("{\"error\":\"Blocked by WAF\",\"type\":\""+type+"\"}");
    }

    private boolean hit(String s, List<Pattern> pp) { return pp.stream().anyMatch(p -> p.matcher(s).find()); }
    private String ip(HttpServletRequest r) { String x=r.getHeader("X-Forwarded-For"); return (x!=null&&!x.isBlank())?x.split(",")[0].trim():r.getRemoteAddr(); }
    private String trim(String s) { return s.substring(0, Math.min(s.length(), 150)); }
    private boolean isPublic(String u) {
        return u.startsWith("/css/") || u.startsWith("/js/") || u.startsWith("/images/")
            || u.equals("/favicon.ico") || u.equals("/login") || u.startsWith("/h2-console")
            || u.startsWith("/ws/") || u.startsWith("/swagger-ui") || u.startsWith("/api-docs")
            || u.startsWith("/v3/api-docs") || u.equals("/api/auth/login")
            || u.equals("/api/public/status")
            || u.startsWith("/api/waf/unblock")
            || u.startsWith("/api/ids/threat-summary")
            || u.startsWith("/api/simulation/status")
            || u.startsWith("/api/simulation/attacker/log");
    }

}
