package com.cybersec.ransomware.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RansomwareFeatureExtractor {

    private final Map<String, List<Long>> requestLogs = new ConcurrentHashMap<>();
    private final Map<String, List<Integer>> payloadSizes = new ConcurrentHashMap<>();

    public Map<String, Double> extractFeatures(HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        long now = System.currentTimeMillis();

        // 1. Frequency (Requests in last 10 seconds)
        List<Long> times = requestLogs.computeIfAbsent(clientIp, k -> new ArrayList<>());
        times.add(now);
        times.removeIf(t -> t < now - 10000);
        double freq = times.size() / 10.0;

        // 2. Duration (Average interval)
        double duration = 0;
        if (times.size() > 1) {
            duration = (times.get(times.size() - 1) - times.get(0)) / (double) times.size();
        }

        // 3. Packet Size Variance
        int size = request.getContentLength() > 0 ? request.getContentLength() : 0;
        List<Integer> sizes = payloadSizes.computeIfAbsent(clientIp, k -> new ArrayList<>());
        sizes.add(size);
        if (sizes.size() > 20) sizes.remove(0);
        double packetVar = calculateVariance(sizes);

        // 4. Entropy Score (of Query String)
        String query = request.getQueryString();
        double entropy = calculateEntropy(query != null ? query : "");

        // 5. File Access Count (Suspicious extensions)
        String uri = request.getRequestURI().toLowerCase();
        double fileAccess = (uri.contains(".enc") || uri.contains(".locked") || uri.contains(".crypto") || uri.contains(".vault")) ? 1.0 : 0.0;

        Map<String, Double> features = new HashMap<>();
        features.put("packetVar", packetVar);
        features.put("entropy", entropy);
        features.put("fileAccess", fileAccess);
        features.put("duration", duration);
        features.put("freq", freq);
        return features;
    }

    private double calculateVariance(List<Integer> data) {
        if (data.isEmpty()) return 0;
        double mean = data.stream().mapToInt(Integer::intValue).average().orElse(0);
        return data.stream().mapToDouble(d -> Math.pow(d - mean, 2)).average().orElse(0);
    }

    private double calculateEntropy(String s) {
        if (s.isEmpty()) return 0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) freq.merge(c, 1, Integer::sum);
        double entropy = 0;
        for (int f : freq.values()) {
            double p = f / (double) s.length();
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy / 8.0; // Normalised to 0-1
    }
}
