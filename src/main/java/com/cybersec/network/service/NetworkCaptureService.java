package com.cybersec.network.service;

import com.cybersec.ids.service.AlertService;
import com.cybersec.network.model.PacketRecord;
import com.cybersec.network.repository.PacketRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Network Capture Service — Wireshark-style HTTP traffic capture.
 * Captures every HTTP request as a packet record, broadcasts live via WebSocket,
 * shows protocol stats, top talkers, ARP table, and MAC address lookup.
 */
@Service
public class NetworkCaptureService {

    private static final Logger log = LoggerFactory.getLogger(NetworkCaptureService.class);

    private final PacketRepository packetRepo;
    private final SimpMessagingTemplate ws;
    private final AlertService alertService;

    @Value("${network.capture.enabled:true}")
    private boolean enabled;

    @Value("${network.capture.interface:lo0}")
    private String iface;

    // Port scan detection — track distinct ports per IP
    private final ConcurrentHashMap<String, Set<Integer>> portActivity = new ConcurrentHashMap<>();

    @Autowired
    public NetworkCaptureService(PacketRepository packetRepo,
                                  @Lazy SimpMessagingTemplate ws,
                                  @Lazy AlertService alertService) {
        this.packetRepo = packetRepo;
        this.ws = ws;
        this.alertService = alertService;
    }

    /**
     * Called from IdsInterceptor on every HTTP request.
     * Creates a packet record and broadcasts it live via WebSocket.
     */
    public void captureHttpPacket(HttpServletRequest req, String clientIp) {
        // Always capture regardless of 'enabled' flag — flag only controls UI toggle
        try {
            String uri         = req.getRequestURI() != null ? req.getRequestURI() : "/";
            String method      = req.getMethod() != null ? req.getMethod() : "GET";
            String ua          = req.getHeader("User-Agent");
            int    dstPort     = req.getServerPort();
            int    contentLen  = req.getContentLength();
            String protocol    = req.isSecure() ? "HTTPS" : (dstPort == 9090 ? "HTTP" : "TCP");

            // Classify protocol from port
            if (dstPort == 80 || dstPort == 8080)  protocol = "HTTP";
            if (dstPort == 443 || dstPort == 8443) protocol = "HTTPS";
            if (dstPort == 53)  protocol = "DNS";

            // Port scan detection
            portActivity.computeIfAbsent(clientIp, k -> ConcurrentHashMap.newKeySet()).add(dstPort);
            boolean suspicious = portActivity.get(clientIp).size() > 15;

            String flags = buildFlags(method, contentLen);
            String info  = method + " " + uri + (contentLen > 0 ? " [" + contentLen + " bytes]" : "");

            PacketRecord pkt = PacketRecord.builder()
                    .srcIp(clientIp)
                    .dstIp(getServerIp())
                    .srcPort(getEphemeralPort(clientIp))
                    .dstPort(dstPort)
                    .protocol(protocol)
                    .length(Math.max(contentLen, uri.length() + method.length() + 12))
                    .info(info)
                    .flags(flags)
                    .interfaceName(iface)
                    .suspicious(suspicious)
                    .build();

            pkt = packetRepo.save(pkt);

            // Broadcast to /topic/network-packets — live feed on Network page
            broadcastPacket(pkt);

            // Port scan alert
            if (portActivity.get(clientIp).size() == 16) {
                try {
                    alertService.fireAlert(clientIp, "PORT_SCAN",
                        "Port scan detected from " + clientIp + " across " +
                        portActivity.get(clientIp).size() + " ports",
                        "NETWORK", "HIGH");
                } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            log.debug("[NETWORK] Capture error: {}", e.getMessage());
        }
    }

    /**
     * Generates ambient background traffic (DNS, MDNS, SSDP, etc.)
     * to simulate a busy network environment.
     */
    @Scheduled(fixedRate = 5000)
    public void generateAmbientTraffic() {
        if (!enabled) return;

        String[] protocols = {"DNS", "MDNS", "SSDP", "IGMP", "ICMP", "TCP", "UDP"};
        String[] internalIps = {"192.168.1.1", "192.168.1.5", "192.168.1.10", "192.168.1.25", "10.0.0.1"};
        String[] externalIps = {"8.8.8.8", "1.1.1.1", "142.250.190.46", "31.13.71.36"};

        Random r = new Random();
        int count = r.nextInt(3) + 1; // 1-3 packets per interval

        for (int i = 0; i < count; i++) {
            String proto = protocols[r.nextInt(protocols.length)];
            String src = internalIps[r.nextInt(internalIps.length)];
            String dst = r.nextBoolean() ? internalIps[r.nextInt(internalIps.length)] : externalIps[r.nextInt(externalIps.length)];
            
            int srcP = 1024 + r.nextInt(64511);
            int dstP = 80;
            String info = "Ambient " + proto + " traffic";

            if ("DNS".equals(proto)) { dstP = 53; info = "Standard query 0x" + Integer.toHexString(r.nextInt(0xFFFF)) + " A google.com"; }
            if ("MDNS".equals(proto)) { dstP = 5353; info = "Multicast DNS query"; }
            if ("SSDP".equals(proto)) { dstP = 1900; info = "M-SEARCH * HTTP/1.1"; }
            if ("ICMP".equals(proto)) { dstP = 0; info = "Echo (ping) request"; }

            PacketRecord pkt = PacketRecord.builder()
                    .srcIp(src)
                    .dstIp(dst)
                    .srcPort(srcP)
                    .dstPort(dstP)
                    .protocol(proto)
                    .length(60 + r.nextInt(1000))
                    .info(info)
                    .flags(r.nextBoolean() ? "ACK" : "PSH, ACK")
                    .interfaceName(iface)
                    .suspicious(false)
                    .build();

            pkt = packetRepo.save(pkt);
            broadcastPacket(pkt);
        }
    }

    private void broadcastPacket(PacketRecord p) {
        try {
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("id",        p.getId());
            data.put("srcIp",     p.getSrcIp());
            data.put("dstIp",     p.getDstIp());
            data.put("srcPort",   p.getSrcPort());
            data.put("dstPort",   p.getDstPort());
            data.put("protocol",  p.getProtocol());
            data.put("length",    p.getLength());
            data.put("info",      p.getInfo());
            data.put("flags",     p.getFlags());
            data.put("suspicious",p.isSuspicious());
            data.put("time",      p.getCapturedAt().toString());
            ws.convertAndSend("/topic/network-packets", data);
        } catch (Exception e) {
            log.debug("[NETWORK] WS broadcast error: {}", e.getMessage());
        }
    }

    /**
     * ARP lookup — returns MAC address for a given IP.
     * Uses system 'arp' command. Works on macOS and Linux.
     */
    public String getMacAddress(String ip) {
        if ("127.0.0.1".equals(ip) || "::1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip)) {
            return "00:00:00:00:00:00 (loopback)";
        }
        // First ping to populate ARP cache
        try {
            InetAddress addr = InetAddress.getByName(ip);
            addr.isReachable(500); // 500ms timeout
        } catch (Exception ignored) {}

        try {
            Process proc = Runtime.getRuntime().exec(new String[]{"arp", "-n", ip});
            String output = new String(proc.getInputStream().readAllBytes()).trim();
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("([0-9a-fA-F]{1,2}[:\\-]){5}[0-9a-fA-F]{1,2}")
                    .matcher(output);
            if (m.find()) return m.group(0).toUpperCase().replace("-", ":");
        } catch (Exception e1) {
            try {
                Process proc = Runtime.getRuntime().exec(new String[]{"ip", "neigh", "show", ip});
                String output = new String(proc.getInputStream().readAllBytes()).trim();
                java.util.regex.Matcher m = java.util.regex.Pattern
                        .compile("([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
                        .matcher(output);
                if (m.find()) return m.group(0).toUpperCase();
            } catch (Exception ignored) {}
        }
        return "N/A — ping the IP first to populate ARP cache";
    }

    /**
     * Returns all entries from the system ARP table (all visible devices on network).
     */
    public List<Map<String, String>> getArpTable() {
        List<Map<String, String>> devices = new ArrayList<>();
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            String[] cmd = (os.contains("mac") || os.contains("bsd"))
                    ? new String[]{"arp", "-a"}
                    : new String[]{"ip", "neigh", "show"};

            Process proc = Runtime.getRuntime().exec(cmd);
            String output = new String(proc.getInputStream().readAllBytes());

            for (String line : output.split("\n")) {
                line = line.trim();
                if (line.isEmpty() || line.contains("incomplete")) continue;

                Map<String, String> dev = new LinkedHashMap<>();

                // macOS: host.local (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0
                java.util.regex.Matcher mac = java.util.regex.Pattern
                        .compile("\\((\\d+\\.\\d+\\.\\d+\\.\\d+)\\)\\s+at\\s+([0-9a-fA-F:]+).*?on\\s+(\\S+)")
                        .matcher(line);
                if (mac.find()) {
                    dev.put("ip",     mac.group(1));
                    dev.put("mac",    mac.group(2).toUpperCase());
                    dev.put("iface",  mac.group(3));
                    dev.put("status", "reachable");
                    devices.add(dev);
                    continue;
                }

                // Linux: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                java.util.regex.Matcher linux = java.util.regex.Pattern
                        .compile("(\\d+\\.\\d+\\.\\d+\\.\\d+).*?lladdr\\s+([0-9a-fA-F:]+)\\s+(\\S+)")
                        .matcher(line);
                if (linux.find()) {
                    dev.put("ip",     linux.group(1));
                    dev.put("mac",    linux.group(2).toUpperCase());
                    dev.put("status", linux.group(3).toLowerCase());
                    devices.add(dev);
                }
            }
        } catch (Exception e) {
            log.debug("[NETWORK] ARP table read failed: {}", e.getMessage());
        }

        // Always include localhost
        boolean hasLocal = devices.stream().anyMatch(d -> "127.0.0.1".equals(d.get("ip")));
        if (!hasLocal) {
            Map<String, String> local = new LinkedHashMap<>();
            local.put("ip", "127.0.0.1");
            local.put("mac", "00:00:00:00:00:00");
            local.put("iface", iface);
            local.put("status", "local");
            devices.add(0, local);
        }
        return devices;
    }

    /** Network interfaces on this machine with MAC addresses. */
    public List<Map<String, String>> getNetworkInterfaces() {
        List<Map<String, String>> result = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
            while (nis != null && nis.hasMoreElements()) {
                NetworkInterface ni = nis.nextElement();
                if (!ni.isUp()) continue;
                Map<String, String> info = new LinkedHashMap<>();
                info.put("name",        ni.getName());
                info.put("displayName", ni.getDisplayName());
                byte[] hw = ni.getHardwareAddress();
                if (hw != null) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < hw.length; i++) {
                        if (i > 0) sb.append(":");
                        sb.append(String.format("%02X", hw[i]));
                    }
                    info.put("mac", sb.toString());
                } else {
                    info.put("mac", ni.isLoopback() ? "00:00:00:00:00:00" : "N/A");
                }
                // Get first non-link-local IP
                String ip = "N/A";
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress addr = addrs.nextElement();
                    if (addr instanceof Inet4Address) { ip = addr.getHostAddress(); break; }
                }
                info.put("ip",  ip);
                info.put("mtu", String.valueOf(ni.getMTU()));
                result.add(info);
            }
        } catch (Exception e) { log.debug("[NETWORK] Interface enum failed: {}", e.getMessage()); }
        return result;
    }

    /** Clear port scan tracking every 5 minutes. */
    @Scheduled(fixedDelay = 300_000)
    public void clearPortActivity() { portActivity.clear(); }

    private String buildFlags(String method, int contentLen) {
        List<String> f = new ArrayList<>();
        f.add("ACK");
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            f.add("PSH"); if (contentLen > 0) f.add("DATA");
        } else {
            f.add("PSH");
        }
        return String.join(", ", f);
    }

    private String getServerIp() {
        try { return InetAddress.getLocalHost().getHostAddress(); }
        catch (Exception e) { return "127.0.0.1"; }
    }

    private int getEphemeralPort(String ip) {
        return 49152 + Math.abs(ip.hashCode() % 16383);
    }

    public boolean isEnabled()           { return enabled; }
    public void setEnabled(boolean v)    { this.enabled = v; log.info("[NETWORK] Capture {}", v ? "STARTED" : "STOPPED"); }
    public String getInterface()         { return iface; }
    public long countPacketsToday()      { return packetRepo.countByCapturedAtAfter(LocalDateTime.now().toLocalDate().atStartOfDay()); }
    public List<PacketRecord> getRecentPackets()    { return packetRepo.findTop200ByOrderByCapturedAtDesc(); }
    public List<PacketRecord> getSuspiciousPackets(){ return packetRepo.findBySuspiciousTrue(); }
    public List<Object[]>    getProtocolStats()     { return packetRepo.countByProtocol(); }
    public List<Object[]>    getTopTalkers()        { return packetRepo.topTalkers(LocalDateTime.now().minusMinutes(30)); }
}
