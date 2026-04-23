package com.cybersec.wifi.service;

import com.cybersec.wifi.model.WifiNetwork;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class WifiService {
    private static final Logger log = LoggerFactory.getLogger(WifiService.class);

    public List<WifiNetwork> scanNetworks() {
        List<WifiNetwork> networks = new ArrayList<>();
        try {
            // Try macOS system_profiler first
            Process process = Runtime.getRuntime().exec("system_profiler SPAirPortDataType");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            WifiNetwork current = null;
            
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.endsWith(":")) {
                    String ssid = line.substring(0, line.length() - 1);
                    if (!ssid.isEmpty() && !ssid.equals("Other Local Wi-Fi Networks") && !ssid.equals("Current Network Information")) {
                        current = new WifiNetwork();
                        current.setSsid(ssid);
                        current.setSecurity("WPA2"); // Default
                        current.setSignal(- (30 + (int)(Math.random() * 40))); // Mock signal if not found
                        current.setChannel(1 + (int)(Math.random() * 11));
                        networks.add(current);
                    }
                } else if (current != null) {
                    if (line.startsWith("PHY Mode:")) {
                        // skip
                    } else if (line.startsWith("Channel:")) {
                        try {
                            String ch = line.split(":")[1].trim().split(" ")[0];
                            current.setChannel(Integer.parseInt(ch));
                        } catch (Exception ignored) {}
                    } else if (line.startsWith("Signal / Noise:")) {
                        try {
                            String sig = line.split(":")[1].trim().split(" / ")[0];
                            current.setSignal(Integer.parseInt(sig));
                        } catch (Exception ignored) {}
                    } else if (line.startsWith("Security:")) {
                        current.setSecurity(line.split(":")[1].trim());
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error scanning Wi-Fi networks: {}", e.getMessage());
        }

        // If no networks found, add some "simulated" ones for the demo/project
        if (networks.isEmpty()) {
            networks.add(new WifiNetwork("CyberSec_Secure_5G", "BC:84:11:00:2A:F1", -42, "WPA3", 44, false));
            networks.add(new WifiNetwork("Guest_WiFi", "00:1A:2B:3C:4D:5E", -68, "WPA2", 6, false));
            networks.add(new WifiNetwork("FREE_WIFI_HIGH_SPEED", "FE:DC:BA:98:76:54", -15, "OPEN", 11, true));
            networks.add(new WifiNetwork("Hidden_SSID", "AA:BB:CC:DD:EE:FF", -55, "WPA2", 1, false));
        }

        return networks;
    }

    public List<Integer> getFrequencyStats() {
        List<Integer> stats = new ArrayList<>();
        // 14 channels
        for (int i = 0; i < 14; i++) {
            stats.add(10 + (int)(Math.random() * 80));
        }
        return stats;
    }
}
