package com.cybersec.ransomware.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@Entity
@Table(name = "ransomware_alerts")
public class RansomwareAlert {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String sourceIp;
    private String targetPath;
    private double threatScore;
    private String detectionType; // ML, BEHAVIORAL, SIGNATURE
    private String status; // DETECTED, BLOCKED, MITIGATED
    private LocalDateTime timestamp;
    
    @Column(length = 2000)
    private String features; // Raw features used for detection
    
    @Column(length = 2000)
    private String explanation; // JSON string of feature contributions (XAI)

    // Constructors
    public RansomwareAlert() {
        this.timestamp = LocalDateTime.now();
    }

    public RansomwareAlert(String sourceIp, String targetPath, double threatScore, String detectionType, String status) {
        this.sourceIp = sourceIp;
        this.targetPath = targetPath;
        this.threatScore = threatScore;
        this.detectionType = detectionType;
        this.status = status;
        this.timestamp = LocalDateTime.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getExplanation() { return explanation; }
    public void setExplanation(String explanation) { this.explanation = explanation; }

    public Map<String, String> getFeaturesMap() {
        if (features == null || features.isEmpty()) return new HashMap<>();
        try {
            // Check if it's the simple toString format or JSON
            if (features.startsWith("{") && features.contains("=")) {
                Map<String, String> map = new HashMap<>();
                String content = features.substring(1, features.length() - 1);
                String[] pairs = content.split(", ");
                for (String pair : pairs) {
                    String[] kv = pair.split("=");
                    if (kv.length == 2) map.put(kv[0], kv[1]);
                }
                return map;
            }
            return new ObjectMapper().readValue(features, new TypeReference<Map<String, String>>() {});
        } catch (Exception e) {
            return new HashMap<>();
        }
    }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getTargetPath() { return targetPath; }
    public void setTargetPath(String targetPath) { this.targetPath = targetPath; }
    public double getThreatScore() { return threatScore; }
    public void setThreatScore(double threatScore) { this.threatScore = threatScore; }
    public String getDetectionType() { return detectionType; }
    public void setDetectionType(String detectionType) { this.detectionType = detectionType; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    public String getFeatures() { return features; }
    public void setFeatures(String features) { this.features = features; }
}
