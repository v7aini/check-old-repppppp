package com.cybersec.ids.controller;

import com.cybersec.ids.engine.AnomalyEngine;
import com.cybersec.ids.engine.SignatureEngine;
import com.cybersec.ids.model.TrafficLog;
import com.cybersec.ids.model.ThreatClassification;
import com.cybersec.ids.model.ThreatClassification.ActionTaken;
import com.cybersec.ids.repository.TrafficLogRepository;
import com.cybersec.ids.service.DdosDetectionService;
import com.cybersec.ids.service.ThreatClassificationService;
import com.cybersec.network.service.NetworkCaptureService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class IdsInterceptor implements HandlerInterceptor {
    private static final Logger log = LoggerFactory.getLogger(IdsInterceptor.class);
    private final TrafficLogRepository trafficRepo;
    private final SignatureEngine sigEngine;
    private final AnomalyEngine anomalyEngine;
    private final NetworkCaptureService networkService;
    private final DdosDetectionService ddosService;
    private final ThreatClassificationService classificationService;
    @Value("${ids.enabled:true}") private boolean enabled;
    private static final String[] SKIP = {"/css/","/js/","/images/","/favicon","/actuator","/ws/","/api/waf/unblock","/swagger-ui","/v3/api-docs","/api-docs","/h2-console","/api/simulation/status","/api/simulation/attacker/log","/api/ids/threat-summary"};

    @Autowired
    public IdsInterceptor(TrafficLogRepository trafficRepo,
                          @Lazy SignatureEngine sigEngine,
                          @Lazy AnomalyEngine anomalyEngine,
                          @Lazy NetworkCaptureService networkService,
                          DdosDetectionService ddosService,
                          @Lazy ThreatClassificationService classificationService) {
        this.trafficRepo = trafficRepo;
        this.sigEngine = sigEngine;
        this.anomalyEngine = anomalyEngine;
        this.networkService = networkService;
        this.ddosService = ddosService;
        this.classificationService = classificationService;
    }

    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object h) throws Exception {
        if (!enabled || shouldSkip(req.getRequestURI())) return true;
        String clientIp = ip(req);
        if ("0:0:0:0:0:0:0:1".equals(clientIp) || "127.0.0.1".equals(clientIp)) return true; // Never evaluate localhost

        // ---- AI Security Assistant: inline classification ----
        try {
            ThreatClassification tc = classificationService.classifyRequest(
                clientIp,
                req.getRequestURI(),
                req.getQueryString(),
                req.getMethod(),
                req.getHeader("User-Agent"),
                null  // body not available in interceptor; handled by WAF filter for POST
            );

            // If the AI blocked this request, return 403 immediately
            if (tc.getActionTaken() == ActionTaken.BLOCKED) {
                res.setStatus(HttpServletResponse.SC_FORBIDDEN);
                res.setContentType("application/json");
                res.getWriter().write(String.format(
                    "{\"error\":\"Blocked by AI Security Assistant\",\"reason\":\"%s\",\"confidence\":%.2f}",
                    tc.getAttackType(), tc.getConfidenceScore()));
                return false;
            }

            // If rate-limited, set a warning header
            if (tc.getActionTaken() == ActionTaken.RATE_LIMITED) {
                res.setHeader("X-CyberSec-Warning", "Rate-limited: " + tc.getAttackType());
            }
        } catch (Exception e) {
            log.debug("[AI-SEC] Classification error (non-blocking): {}", e.getMessage());
        }

        // ---- Standard IDS pipeline (async) ----
        TrafficLog tl = TrafficLog.builder().clientIp(clientIp).requestUri(req.getRequestURI())
                .queryString(req.getQueryString()).method(req.getMethod()).userAgent(req.getHeader("User-Agent")).build();
        trafficRepo.save(tl);

        Thread.ofVirtual().start(() -> {
            try {
                sigEngine.evaluate(tl);
                anomalyEngine.analyse(tl);
                ddosService.trackPacket(clientIp, req.getMethod());
                networkService.captureHttpPacket(req, clientIp);
            } catch (Exception e) { log.error("[IDS] Engine error: {}", e.getMessage()); }
        });
        return true;
    }

    /** Reset the per-IP request counters every 10 seconds for DDoS/frequency heuristics */
    @Scheduled(fixedDelay = 10_000)
    public void resetCounters() {
        classificationService.resetRequestCounters();
    }

    private boolean shouldSkip(String uri) { for (String p : SKIP) if (uri.startsWith(p)) return true; return false; }
    private String ip(HttpServletRequest r) { String x = r.getHeader("X-Forwarded-For"); return (x!=null&&!x.isBlank())?x.split(",")[0].trim():r.getRemoteAddr(); }
}
