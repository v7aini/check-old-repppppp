package com.cybersec.waf.service;
import com.cybersec.waf.model.WafBlock;
import com.cybersec.waf.repository.WafBlockRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class WafRuleService {
    private final WafBlockRepository repo;
    @Autowired public WafRuleService(WafBlockRepository repo) { this.repo = repo; }
    public Optional<String> matchCustomRules(String target) { return Optional.empty(); }
    public WafBlock saveBlock(WafBlock block) { return repo.save(block); }
    public long countBlocksInLast24h() { return repo.countByBlockedAtAfter(LocalDateTime.now().minusHours(24)); }
}
