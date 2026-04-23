package com.cybersec.ids.engine;
import com.cybersec.ids.model.TrafficLog;
import com.cybersec.ids.repository.SignatureRuleRepository;
import com.cybersec.ids.service.AlertService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@Component
public class SignatureEngine {
    private static final Logger log = LoggerFactory.getLogger(SignatureEngine.class);
    private final SignatureRuleRepository ruleRepo;
    private final AlertService alertService;

    @Autowired
    public SignatureEngine(SignatureRuleRepository ruleRepo,
                           @Lazy AlertService alertService) {  // @Lazy breaks the cycle
        this.ruleRepo = ruleRepo; this.alertService = alertService;
    }

    public void evaluate(TrafficLog tl) {
        String target = tl.getMethod() + " " + tl.getRequestUri()
            + (tl.getQueryString() != null ? "?" + tl.getQueryString() : "")
            + (tl.getUserAgent() != null ? " " + tl.getUserAgent() : "");
        ruleRepo.findByEnabledTrue().forEach(rule -> {
            try {
                if (Pattern.compile(rule.getRegexPattern(), Pattern.CASE_INSENSITIVE | Pattern.DOTALL)
                           .matcher(target).find()) {
                    log.info("[SIG] '{}' matched {}", rule.getRuleName(), tl.getClientIp());
                    alertService.fireAlert(tl.getClientIp(), rule.getAttackType(),
                        "Signature: " + rule.getRuleName() + " | URI: " + tl.getRequestUri(),
                        "IDS_SIGNATURE", rule.getSeverity());
                }
            } catch (PatternSyntaxException e) { log.error("[SIG] Bad regex #{}: {}", rule.getId(), e.getMessage()); }
        });
    }
}
