package com.cybersec.ransomware.service;

import com.cybersec.ransomware.ml.RansomwareRandomForest;
import com.cybersec.ransomware.model.RansomwareAlert;
import com.cybersec.ransomware.model.RansomwareAlertRepository;
import com.cybersec.telegram.TelegramAlertService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Map;

@Component
public class RansomwareInterceptor implements HandlerInterceptor {

    @Autowired
    private RansomwareFeatureExtractor extractor;

    @Autowired
    private RansomwareRandomForest mlModel;

    @Autowired
    private RansomwareAlertRepository alertRepository;

    @Autowired
    private TelegramAlertService telegramService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        // Skip static resources
        String uri = request.getRequestURI();
        if (uri.contains("/css/") || uri.contains("/js/") || uri.contains("/images/") || uri.contains("/api/")) {
            return true;
        }

        Map<String, Double> features = extractor.extractFeatures(request);
        double[] distribution = mlModel.getDistribution(
            features.get("packetVar"),
            features.get("entropy"),
            features.get("fileAccess"),
            features.get("duration"),
            features.get("freq")
        );

        double ransomwareProb = distribution[1];

        if (ransomwareProb > 0.7) { // High threshold for real-time blocking
            Map<String, Double> explanation = mlModel.explainPrediction(
                features.get("packetVar"),
                features.get("entropy"),
                features.get("fileAccess"),
                features.get("duration"),
                features.get("freq")
            );

            RansomwareAlert alert = new RansomwareAlert(
                request.getRemoteAddr(),
                uri,
                ransomwareProb,
                "ML_ENSEMBLE_DETECTION",
                "BLOCKED"
            );
            alert.setFeatures(features.toString());
            try {
                alert.setExplanation(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(explanation));
            } catch (Exception e) {
                alert.setExplanation(explanation.toString());
            }
            alertRepository.save(alert);

            telegramService.sendCustomMessage("🚨 [ENSEMBLE RANSOMWARE BLOCK] 🚨\n" +
                "IP: " + request.getRemoteAddr() + "\n" +
                "Confidence: " + String.format("%.1f%%", ransomwareProb * 100) + "\n" +
                "Primary Trigger: " + explanation.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey)
                    .orElse("Multiple Factors") + "\n" +
                "URI: " + uri);
            
            try {
                response.sendError(403, "Access Denied: Suspicious Ransomware Behavior Detected");
            } catch (Exception e) {}
            return false;
        }

        return true;
    }
}
