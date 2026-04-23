package com.cybersec.investigate.service;

import com.cybersec.ids.repository.AlertRepository;
import com.cybersec.investigate.model.DeviceInvestigation;
import com.cybersec.investigate.model.DeviceInvestigation.InvestigationStatus;
import com.cybersec.investigate.repository.InvestigationRepository;
import com.cybersec.network.repository.PacketRepository;
import com.cybersec.network.service.NetworkCaptureService;
import com.cybersec.shared.service.GeolocationService;
import com.cybersec.telegram.TelegramAlertService;
import com.cybersec.waf.service.IpFirewallService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Investigation Service — the core of the Investigation Tool.
 * Allows you to:
 *  - Add a device under investigation (by IP)
 *  - Block it immediately in WAF
 *  - Monitor its traffic in real time
 *  - Resolve MAC address via ARP
 *  - Notify Telegram when a device is blocked
 */
@Service
public class InvestigationService {

    private static final Logger log = LoggerFactory.getLogger(InvestigationService.class);

    private final InvestigationRepository repo;
    private final IpFirewallService firewallService;
    private final NetworkCaptureService networkService;
    private final TelegramAlertService telegramService;
    private final AlertRepository alertRepo;
    private final PacketRepository packetRepo;
    private final GeolocationService geoService;

    @Autowired
    public InvestigationService(InvestigationRepository repo,
                                 IpFirewallService firewallService,
                                 @Lazy NetworkCaptureService networkService,
                                 @Lazy TelegramAlertService telegramService,
                                 AlertRepository alertRepo,
                                 PacketRepository packetRepo,
                                 GeolocationService geoService) {
        this.repo = repo; this.firewallService = firewallService;
        this.networkService = networkService; this.telegramService = telegramService;
        this.alertRepo = alertRepo; this.packetRepo = packetRepo;
        this.geoService = geoService;
    }

    /**
     * Start investigating a device — resolves hostname + MAC, counts alerts.
     */
    @Transactional
    public DeviceInvestigation startInvestigation(String ip, String reason) {
        System.err.println("[DEBUG] InvestigationService.startInvestigation called for IP: " + ip);
        if (ip == null || ip.trim().isEmpty()) {
            throw new IllegalArgumentException("IP address cannot be empty");
        }

        try {
            Optional<DeviceInvestigation> existing = repo.findByIpAddress(ip);
            if (existing.isPresent()) {
                System.err.println("[DEBUG] Found existing investigation for " + ip);
                return existing.get();
            }

            System.err.println("[DEBUG] Resolving data for new investigation: " + ip);
            String mac = "Unknown";
            try {
                mac = networkService.getMacAddress(ip);
            } catch (Exception e) {
                System.err.println("[DEBUG] MAC resolution failed: " + e.getMessage());
            }

            String hostname = ip;
            try {
                hostname = resolveHostname(ip);
            } catch (Exception e) {
                System.err.println("[DEBUG] Hostname resolution failed: " + e.getMessage());
            }

            int alertCount = 0;
            try {
                alertCount = alertRepo.findBySourceIpOrderByDetectedAtDesc(ip).size();
            } catch (Exception e) {
                System.err.println("[DEBUG] Alert count fetch failed: " + e.getMessage());
            }

            DeviceInvestigation inv = DeviceInvestigation.builder()
                    .ipAddress(ip)
                    .macAddress(mac)
                    .hostname(hostname)
                    .status(InvestigationStatus.MONITORING)
                    .reason(reason != null && !reason.isEmpty() ? reason : "Manual investigation")
                    .threatScore(Math.min(100, alertCount * 10))
                    .build();

            inv.setAlertCount(alertCount);
            System.err.println("[DEBUG] Saving investigation to repo...");
            inv = repo.save(inv);
            System.err.println("[DEBUG] Saved successfully. ID: " + inv.getId());
            return inv;
        } catch (Exception e) {
            System.err.println("[DEBUG] CRITICAL ERROR in startInvestigation: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Block a device — adds to WAF blocklist + notifies Telegram.
     */
    @Transactional
    public DeviceInvestigation blockDevice(Long id, String reason) {
        DeviceInvestigation inv = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Investigation not found: " + id));

        inv.setStatus(InvestigationStatus.BLOCKED);
        inv.setReason(reason);
        inv.setUpdatedAt(LocalDateTime.now());
        inv = repo.save(inv);

        // Block in WAF
        firewallService.blockIp(inv.getIpAddress(), "Investigation block: " + reason, null);

        // Notify Telegram
        String msg = String.format(
            "🚫 *DEVICE BLOCKED*\n\n" +
            "🌐 IP: `%s`\n" +
            "💻 MAC: `%s`\n" +
            "🖥 Hostname: %s\n" +
            "📋 Reason: %s\n" +
            "⚠️ Alerts: %d\n" +
            "🔴 Score: %d/100\n" +
            "⏰ Time: %s",
            inv.getIpAddress(), inv.getMacAddress(),
            inv.getHostname() != null ? inv.getHostname() : "unknown",
            reason, inv.getAlertCount(), inv.getThreatScore(),
            LocalDateTime.now().toString().replace("T", " ").substring(0, 19)
        );
        telegramService.sendCustomMessage(msg);
        inv.setTelegramNotified(true);
        return repo.save(inv);
    }

    /**
     * Whitelist a device — removes from WAF blocklist.
     */
    @Transactional
    public DeviceInvestigation whitelistDevice(Long id) {
        DeviceInvestigation inv = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Investigation not found: " + id));
        inv.setStatus(InvestigationStatus.WHITELISTED);
        inv.setUpdatedAt(LocalDateTime.now());
        firewallService.unblockIp(inv.getIpAddress());
        log.info("[INVESTIGATE] Whitelisted {}", inv.getIpAddress());
        return repo.save(inv);
    }

    /**
     * Resolve investigation — mark as done.
     */
    @Transactional
    public DeviceInvestigation resolveInvestigation(Long id, String notes) {
        DeviceInvestigation inv = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Investigation not found: " + id));
        inv.setStatus(InvestigationStatus.RESOLVED);
        inv.setNotes(notes);
        inv.setUpdatedAt(LocalDateTime.now());
        return repo.save(inv);
    }

    /**
     * Refresh device data — re-resolve MAC, recount alerts.
     */
    @Transactional
    public DeviceInvestigation refreshDevice(Long id) {
        DeviceInvestigation inv = repo.findById(id)
                .orElseThrow(() -> new RuntimeException("Investigation not found: " + id));
        inv.setMacAddress(networkService.getMacAddress(inv.getIpAddress()));
        inv.setHostname(resolveHostname(inv.getIpAddress()));
        inv.setAlertCount(alertRepo.findBySourceIpOrderByDetectedAtDesc(inv.getIpAddress()).size());
        inv.setPacketCount(packetRepo.findBySrcIpOrderByCapturedAtDesc(inv.getIpAddress()).size());
        inv.setThreatScore(Math.min(100, inv.getAlertCount() * 10));
        inv.setUpdatedAt(LocalDateTime.now());
        return repo.save(inv);
    }

    public List<DeviceInvestigation> getAllInvestigations() {
        return repo.findAllByOrderByUpdatedAtDesc();
    }

    public Optional<DeviceInvestigation> findById(Long id) { return repo.findById(id); }

    public Map<String, Object> getDeviceProfile(String ip) {
        Map<String, Object> profile = new LinkedHashMap<>();
        profile.put("ip",       ip);
        profile.put("mac",      networkService.getMacAddress(ip));
        profile.put("hostname", resolveHostname(ip));
        profile.put("alerts",   alertRepo.findBySourceIpOrderByDetectedAtDesc(ip));
        profile.put("packets",  packetRepo.findBySrcIpOrderByCapturedAtDesc(ip));
        profile.put("inArp",    networkService.getArpTable().stream()
                                 .anyMatch(d -> ip.equals(d.get("ip"))));
        
        Map<String, Object> geo = geoService.getGeoData(ip);
        profile.put("country", geo.get("country"));
        profile.put("lat", geo.get("lat"));
        profile.put("lon", geo.get("lon"));
        
        return profile;
    }

    private String resolveHostname(String ip) {
        try { return InetAddress.getByName(ip).getHostName(); }
        catch (Exception e) { return ip; }
    }
}
