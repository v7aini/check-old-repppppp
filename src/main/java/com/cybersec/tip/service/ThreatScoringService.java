package com.cybersec.tip.service;
import com.cybersec.tip.model.IocIndicator;
import com.cybersec.tip.repository.IocIndicatorRepository;
import com.cybersec.waf.service.IpFirewallService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class ThreatScoringService {
    private static final Logger log = LoggerFactory.getLogger(ThreatScoringService.class);
    private final IocIndicatorRepository iocRepo;
    private final IpFirewallService firewallService;
    @Value("${tip.cvss.auto-block-threshold:80}") private int autoBlockThreshold;

    @Autowired
    public ThreatScoringService(IocIndicatorRepository iocRepo, IpFirewallService firewallService) {
        this.iocRepo = iocRepo; this.firewallService = firewallService;
    }

    public int scoreIp(String ip) {
        try {
            Optional<IocIndicator> ioc = iocRepo.findActiveByIndicatorValue(ip);
            if (ioc.isPresent()) {
                int score = ioc.get().getThreatScore();
                if (score >= autoBlockThreshold) firewallService.blockIp(ip, "TIP auto-block score=" + score, null);
                return Math.min(100, score);
            }
        } catch (Exception e) { log.debug("[TIP] Score lookup failed for {}: {}", ip, e.getMessage()); }
        return 0;
    }

    public int scoreDomain(String domain) {
        return iocRepo.findActiveByIndicatorValue(domain).map(IocIndicator::getThreatScore).orElse(0);
    }

    public Optional<IocIndicator> lookupIndicator(String value) {
        return iocRepo.findActiveByIndicatorValue(value);
    }

    public static String getThreatLevel(int score) {
        if (score >= 80) return "CRITICAL";
        if (score >= 60) return "HIGH";
        if (score >= 40) return "MEDIUM";
        if (score >= 20) return "LOW";
        return "INFO";
    }
}
