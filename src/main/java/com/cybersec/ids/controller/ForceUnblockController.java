package com.cybersec.ids.controller;
import com.cybersec.waf.repository.IpBlocklistRepository;
import com.cybersec.ids.repository.AlertRepository;
import com.cybersec.waf.service.IpFirewallService;
import com.cybersec.waf.service.RateLimiterService;
import com.cybersec.ids.service.ThreatClassificationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import jakarta.annotation.PostConstruct;

@Component
public class ForceUnblockController {
    @Autowired IpBlocklistRepository ipRepo;
    @Autowired AlertRepository alertRepo;
    @Autowired IpFirewallService fw;
    @Autowired RateLimiterService rl;
    @Autowired ThreatClassificationService ts;
    
    @PostConstruct
    public void unblock() {
        System.out.println("========== AUTO UNBLOCKING LOCALHOST ==========");
        String ip = "0:0:0:0:0:0:0:1";
        fw.unblockIp(ip);
        rl.clearStrikes(ip);
        ts.clearFailedLogins(ip);
        try { alertRepo.deleteBySourceIp(ip); } catch (Exception e) {}
    }
}
