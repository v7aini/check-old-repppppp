package com.cybersec.shared.config;
import com.cybersec.ids.model.SignatureRule;
import com.cybersec.ids.repository.SignatureRuleRepository;
import com.cybersec.shared.auth.UserRepository;
import com.cybersec.shared.model.AppUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import java.util.List;

@Configuration
public class DataInitializer {
    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);
    private final SignatureRuleRepository ruleRepo;
    private final UserRepository userRepo;
    private final PasswordEncoder encoder;

    @Autowired
    public DataInitializer(SignatureRuleRepository ruleRepo, UserRepository userRepo, PasswordEncoder encoder) {
        this.ruleRepo = ruleRepo; this.userRepo = userRepo; this.encoder = encoder;
    }

    @Bean
    public CommandLineRunner seed() {
        return args -> {
            seedUsers();
            seedRules();
            log.info("[INIT] Seeding complete.");
        };
    }

    private void seedUsers() {
        if (userRepo.findByUsername("admin").isPresent()) return;
        userRepo.save(AppUser.builder().username("admin").password(encoder.encode("admin123")).role("ADMIN").email("admin@cybersec.local").build());
        userRepo.save(AppUser.builder().username("analyst").password(encoder.encode("analyst123")).role("ANALYST").email("analyst@cybersec.local").build());
        userRepo.save(AppUser.builder().username("viewer").password(encoder.encode("viewer123")).role("VIEWER").email("viewer@cybersec.local").build());
        log.info("[INIT] Default users created: admin / analyst / viewer");
    }

    private void seedRules() {
        if (ruleRepo.count() > 0) return;
        List<SignatureRule> rules = List.of(
            rule("SQLi UNION SELECT",   "(?i)union\\s+select",                              "SQL_INJECTION","HIGH"),
            rule("SQLi DROP TABLE",     "(?i)drop\\s+table",                                "SQL_INJECTION","CRITICAL"),
            rule("SQLi OR 1=1",         "(?i)(or|and)\\s+['\"]?1['\"]?\\s*=\\s*['\"]?1",  "SQL_INJECTION","HIGH"),
            rule("SQLi Comment bypass", "--\\s*$|/\\*.*?\\*/",                              "SQL_INJECTION","MEDIUM"),
            rule("SQLi SLEEP/BENCH",    "(?i)(sleep|benchmark)\\s*\\(",                     "SQL_INJECTION","HIGH"),
            rule("XSS Script tag",      "(?i)<script[^>]*>",                                "XSS","HIGH"),
            rule("XSS Event handler",   "(?i)on(error|load|click|mouseover)\\s*=",         "XSS","HIGH"),
            rule("XSS javascript:",     "(?i)javascript\\s*:",                              "XSS","MEDIUM"),
            rule("LFI Path traversal",  "\\.\\./|\\.\\\\|\\.%2f",                           "LFI","HIGH"),
            rule("LFI Sensitive files", "(?i)/etc/(passwd|shadow|hosts|sudoers)",           "LFI","CRITICAL"),
            rule("LFI Windows paths",   "(?i)c:[/\\\\]windows",                             "LFI","HIGH"),
            rule("CMD Shell commands",  "(?i)(;|\\|\\||&&)\\s*(ls|cat|id|whoami|uname)",   "CMD_INJECTION","CRITICAL"),
            rule("CMD Backtick exec",   "`[^`]{1,200}`",                                    "CMD_INJECTION","HIGH"),
            rule("Scanner sqlmap",      "(?i)sqlmap",                                       "SCANNER","MEDIUM"),
            rule("Scanner Nikto",       "(?i)nikto",                                        "SCANNER","MEDIUM"),
            rule("Scanner Masscan",     "(?i)masscan",                                      "SCANNER","LOW"),
            rule("Recon wp-admin",      "(?i)/wp-admin|/wp-login",                         "RECON","LOW"),
            rule("Recon phpmyadmin",    "(?i)/phpmyadmin|/pma/",                            "RECON","MEDIUM"),
            rule("SSRF Internal IP",    "(?i)(169\\.254\\.|192\\.168\\.|127\\.)",           "SSRF","HIGH"),
            rule("XXE DOCTYPE",         "(?i)<!entity|<!doctype.*system",                  "XXE","HIGH")
        );
        ruleRepo.saveAll(rules);
        log.info("[INIT] Seeded {} signature rules", rules.size());
    }

    private SignatureRule rule(String name, String pattern, String type, String sev) {
        return SignatureRule.builder().ruleName(name).regexPattern(pattern)
                .attackType(type).severity(sev).description("Built-in: "+name).enabled(true).build();
    }
}
