package com.cybersec.dashboard.controller;

import com.cybersec.ids.model.Alert;
import com.cybersec.ids.repository.SignatureRuleRepository;
import com.cybersec.ids.repository.TrafficLogRepository;
import com.cybersec.ids.service.AlertService;
import com.cybersec.investigate.model.DeviceInvestigation;
import com.cybersec.investigate.service.InvestigationService;
import com.cybersec.network.service.NetworkCaptureService;
import com.cybersec.telegram.TelegramAlertService;
import com.cybersec.tip.model.IocIndicator;
import com.cybersec.tip.repository.IocIndicatorRepository;
import com.cybersec.tip.service.FeedAggregatorService;
import com.cybersec.waf.service.WafRuleService;
import com.cybersec.ransomware.model.RansomwareAlertRepository;
import com.cybersec.ransomware.service.RansomwareSimulatorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import java.time.LocalDateTime;
import java.util.*;

@Controller
public class DashboardController {

    private final AlertService alertService;
    private final WafRuleService wafService;
    private final IocIndicatorRepository iocRepo;
    private final TrafficLogRepository trafficRepo;
    private final SignatureRuleRepository ruleRepo;
    private final FeedAggregatorService feedService;
    private final NetworkCaptureService networkService;
    private final InvestigationService investigationService;
    private final TelegramAlertService telegramService;
    private final RansomwareAlertRepository ransomwareRepo;
    private final RansomwareSimulatorService ransomwareService;

    @Autowired
    public DashboardController(AlertService a, WafRuleService w, IocIndicatorRepository i,
                                TrafficLogRepository t, SignatureRuleRepository r,
                                FeedAggregatorService f, NetworkCaptureService n,
                                InvestigationService inv, TelegramAlertService tg,
                                RansomwareAlertRepository rr, RansomwareSimulatorService rs) {
        this.alertService=a; this.wafService=w; this.iocRepo=i;
        this.trafficRepo=t; this.ruleRepo=r; this.feedService=f;
        this.networkService=n; this.investigationService=inv; this.telegramService=tg;
        this.ransomwareRepo=rr; this.ransomwareService=rs;
    }

    @GetMapping({"/", "/dashboard"})
    public String dashboard(Model m) {
        m.addAttribute("alertsToday",   alertService.countAlertsToday());
        m.addAttribute("wafBlocks24h",  wafService.countBlocksInLast24h());
        m.addAttribute("iocCount",      iocRepo.countByStatus(IocIndicator.IocStatus.ACTIVE));
        m.addAttribute("trafficToday",  trafficRepo.countByRequestTimeAfter(LocalDateTime.now().toLocalDate().atStartOfDay()));
        m.addAttribute("recentAlerts",  alertService.getRecentAlerts(20));
        m.addAttribute("alertTypeData", alertService.getAlertCountsByType());
        m.addAttribute("packetsToday",  networkService.countPacketsToday());
        m.addAttribute("investigations",investigationService.getAllInvestigations().size());
        List<String> labels = new ArrayList<>(); List<Long> counts = new ArrayList<>();
        for (Object[] row : trafficRepo.countByHour(LocalDateTime.now().minusHours(24))) {
            labels.add(row[0]+":00"); counts.add((Long)row[1]);
        }
        m.addAttribute("trafficHours",  labels);
        m.addAttribute("trafficCounts", counts);
        m.addAttribute("activeRules",   ruleRepo.findByEnabledTrue().size());
        m.addAttribute("tipFeedEnabled",feedService.isFeedEnabled());
        m.addAttribute("telegramEnabled",telegramService.isEnabled());
        m.addAttribute("captureEnabled", networkService.isEnabled());
        return "dashboard/index";
    }

    @GetMapping("/ids")
    public String ids(Model m) {
        m.addAttribute("openAlerts",    alertService.getOpenAlerts());
        m.addAttribute("allRules",      ruleRepo.findAll());
        m.addAttribute("criticalCount", alertService.countBySeverity(Alert.Severity.CRITICAL));
        m.addAttribute("highCount",     alertService.countBySeverity(Alert.Severity.HIGH));
        return "ids/index";
    }

    @GetMapping("/ids/alert/{id}")
    public String alertDetail(@PathVariable("id") Long id, Model m) {
        alertService.findById(id).ifPresent(a -> m.addAttribute("alert", a));
        return "ids/alert-detail";
    }

    @PostMapping("/ids/alert/{id}/status")
    public String updateStatus(@PathVariable("id") Long id, @RequestParam("status") String status,
                               @RequestParam(value="notes", required=false) String notes) {
        alertService.updateStatus(id, Alert.AlertStatus.valueOf(status), notes);
        return "redirect:/ids/alert/"+id;
    }

    @GetMapping("/waf")
    public String waf(Model m) { m.addAttribute("blocks24h", wafService.countBlocksInLast24h()); return "waf/index"; }

    @GetMapping("/tip")
    public String tip(Model m) {
        m.addAttribute("topThreats",     iocRepo.findTopThreatsByScore(20));
        m.addAttribute("activeIocCount", iocRepo.countByStatus(IocIndicator.IocStatus.ACTIVE));
        m.addAttribute("lastFeedRun",    feedService.getLastRunTime());
        m.addAttribute("lastIngest",     feedService.getLastIngestCount());
        return "tip/index";
    }

    @PostMapping("/tip/feed/trigger")
    public String triggerFeed() { feedService.triggerManualIngest(); return "redirect:/tip"; }

    @GetMapping("/network")
    public String network(Model m) {
        m.addAttribute("recentPackets",   networkService.getRecentPackets());
        m.addAttribute("suspiciousCount", networkService.getSuspiciousPackets().size());
        m.addAttribute("packetsToday",    networkService.countPacketsToday());
        m.addAttribute("captureEnabled",  networkService.isEnabled());
        m.addAttribute("interfaces",      networkService.getNetworkInterfaces());
        m.addAttribute("arpTable",        networkService.getArpTable());
        Map<String,Long> protocols = new LinkedHashMap<>();
        for (Object[] r : networkService.getProtocolStats()) protocols.put((String)r[0],(Long)r[1]);
        m.addAttribute("protocols", protocols);
        Map<String,Long> talkers = new LinkedHashMap<>();
        for (Object[] r : networkService.getTopTalkers()) talkers.put((String)r[0],(Long)r[1]);
        m.addAttribute("topTalkers", talkers);
        return "network/index";
    }

    @PostMapping("/network/capture/toggle")
    public String toggleCapture(@RequestParam("enable") boolean enable) {
        networkService.setEnabled(enable);
        return "redirect:/network";
    }

    @GetMapping("/investigate")
    public String investigate(Model m) {
        m.addAttribute("investigations", investigationService.getAllInvestigations());
        m.addAttribute("arpTable",       networkService.getArpTable());
        return "investigate/index";
    }

    @PostMapping("/investigate/start")
    public String startInvestigation(@RequestParam("ip") String ip, 
                                   @RequestParam(value="reason", defaultValue="Manual") String reason,
                                   RedirectAttributes ra) {
        System.err.println("[DEBUG] Controller receiving startInvestigation for IP: " + ip);
        try {
            DeviceInvestigation inv = investigationService.startInvestigation(ip, reason);
            System.err.println("[DEBUG] Investigation started successfully, redirecting to ID: " + inv.getId());
            return "redirect:/investigate/" + inv.getId();
        } catch (Exception e) {
            System.err.println("[DEBUG] Controller caught error starting investigation: " + e.getMessage());
            ra.addFlashAttribute("error", "Investigation failed: " + e.getMessage());
            return "redirect:/investigate";
        }
    }

    @GetMapping("/investigate/{id}")
    public String investigateDetail(@PathVariable("id") Long id, Model m, RedirectAttributes ra) {
        try {
            DeviceInvestigation inv = investigationService.findById(id)
                    .orElseThrow(() -> new RuntimeException("Investigation not found"));
            m.addAttribute("inv", inv);
            m.addAttribute("profile", investigationService.getDeviceProfile(inv.getIpAddress()));
            return "investigate/detail";
        } catch (Exception e) {
            ra.addFlashAttribute("error", "Error loading details: " + e.getMessage());
            return "redirect:/investigate";
        }
    }

    @PostMapping("/investigate/{id}/block")
    public String blockDevice(@PathVariable("id") Long id, @RequestParam(value="reason", defaultValue="Blocked via UI") String reason) {
        investigationService.blockDevice(id, reason);
        return "redirect:/investigate";
    }

    @PostMapping("/investigate/{id}/whitelist")
    public String whitelistDevice(@PathVariable("id") Long id) {
        investigationService.whitelistDevice(id);
        return "redirect:/investigate";
    }

    @PostMapping("/investigate/{id}/resolve")
    public String resolveInvestigation(@PathVariable("id") Long id, @RequestParam(value="notes", required=false) String notes) {
        investigationService.resolveInvestigation(id, notes);
        return "redirect:/investigate";
    }

    @PostMapping("/investigate/{id}/refresh")
    public String refreshDevice(@PathVariable("id") Long id) {
        investigationService.refreshDevice(id);
        return "redirect:/investigate";
    }

    @GetMapping("/ransomware")
    public String ransomware(Model m) {
        m.addAttribute("alerts", ransomwareRepo.findTop10ByOrderByTimestampDesc());
        m.addAttribute("totalDetections", ransomwareRepo.count());
        return "ransomware/index";
    }

    @GetMapping("/login")
    public String login() { return "login"; }
}
