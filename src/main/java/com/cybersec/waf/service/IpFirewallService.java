package com.cybersec.waf.service;
import com.cybersec.waf.model.IpBlockEntry;
import com.cybersec.waf.repository.IpBlocklistRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;

@Service
public class IpFirewallService {
    private static final Logger log = LoggerFactory.getLogger(IpFirewallService.class);
    private final IpBlocklistRepository repo;

    @Autowired
    public IpFirewallService(IpBlocklistRepository repo) { this.repo = repo; }

    public boolean isBlocked(String ip) { return repo.findActiveByIp(ip).isPresent(); }

    public void blockIp(String ip, String reason, LocalDateTime expiry) {
        if ("0:0:0:0:0:0:0:1".equals(ip) || "127.0.0.1".equals(ip)) return; // Never block localhost
        if (isBlocked(ip)) return;
        IpBlockEntry e = IpBlockEntry.builder().ipAddress(ip).reason(reason)
                .blockedAt(LocalDateTime.now()).expiresAt(expiry).active(true).build();
        repo.save(e);
        log.info("[FIREWALL] Blocked IP: {}", ip);
    }

    public void unblockIp(String ip) {
        repo.findActiveByIp(ip).ifPresent(e -> { e.setActive(false); repo.save(e); });
    }
}
