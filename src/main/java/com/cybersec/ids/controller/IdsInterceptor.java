package com.cybersec.ids.controller;

import com.cybersec.ids.engine.AnomalyEngine;
import com.cybersec.ids.engine.SignatureEngine;
import com.cybersec.ids.model.TrafficLog;
import com.cybersec.ids.repository.TrafficLogRepository;
import com.cybersec.ids.service.DdosDetectionService;
import com.cybersec.network.service.NetworkCaptureService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
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
    @Value("${ids.enabled:true}") private boolean enabled;
    private static final String[] SKIP = {"/css/","/js/","/images/","/favicon","/actuator","/ws/"};

    @Autowired
    public IdsInterceptor(TrafficLogRepository trafficRepo,
                          @Lazy SignatureEngine sigEngine,
        @Lazy AnomalyEngine anomalyEngine,
        @Lazy NetworkCaptureService networkService,
        DdosDetectionService ddosService) {
    this.trafficRepo = trafficRepo; this.sigEngine = sigEngine;
    this.anomalyEngine = anomalyEngine; this.networkService = networkService;
    this.ddosService = ddosService;
}

    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse res, Object h) {
        if (!enabled || shouldSkip(req.getRequestURI())) return true;
        String clientIp = ip(req);

        TrafficLog tl = TrafficLog.builder().clientIp(clientIp).requestUri(req.getRequestURI())
                .queryString(req.getQueryString()).method(req.getMethod()).userAgent(req.getHeader("User-Agent")).build();
        trafficRepo.save(tl);

        Thread.ofVirtual().start(() -> {
            try {
                sigEngine.evaluate(tl);
                anomalyEngine.analyse(tl);
                ddosService.trackPacket(clientIp, req.getMethod());
                networkService.captureHttpPacket(req, clientIp); // Packet capture
            } catch (Exception e) { log.error("[IDS] Engine error: {}", e.getMessage()); }
        });
        return true;
    }

    private boolean shouldSkip(String uri) { for (String p : SKIP) if (uri.startsWith(p)) return true; return false; }
    private String ip(HttpServletRequest r) { String x = r.getHeader("X-Forwarded-For"); return (x!=null&&!x.isBlank())?x.split(",")[0].trim():r.getRemoteAddr(); }
}
