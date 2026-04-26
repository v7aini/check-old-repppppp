package com.cybersec.ids.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Record of each ML classification decision for an incoming request.
 * Stores the classification outcome (SAFE / SUSPICIOUS / MALICIOUS),
 * the confidence score, and what action the system took.
 */
@Entity
@Table(name = "threat_classifications", indexes = {
    @Index(name = "idx_tc_ip",     columnList = "client_ip"),
    @Index(name = "idx_tc_time",   columnList = "classified_at"),
    @Index(name = "idx_tc_class",  columnList = "classification")
})
public class ThreatClassification {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_ip", nullable = false, length = 45)
    private String clientIp;

    @Column(name = "request_uri", length = 500)
    private String requestUri;

    @Column(name = "request_payload", length = 2000)
    private String requestPayload;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 15)
    private Classification classification = Classification.SAFE;

    @Column(name = "confidence_score", nullable = false)
    private double confidenceScore = 0.0;

    @Column(name = "attack_type", length = 60)
    private String attackType;

    @Column(name = "matched_pattern_id")
    private Long matchedPatternId;

    @Enumerated(EnumType.STRING)
    @Column(name = "action_taken", nullable = false, length = 20)
    private ActionTaken actionTaken = ActionTaken.ALLOWED;

    @Column(name = "classified_at", nullable = false)
    private LocalDateTime classifiedAt = LocalDateTime.now();

    @Column(name = "response_time_ms")
    private long responseTimeMs;

    public enum Classification { SAFE, SUSPICIOUS, MALICIOUS }
    public enum ActionTaken    { ALLOWED, RATE_LIMITED, BLOCKED, ALERT_ONLY }

    // ---- getters ----
    public Long getId()                        { return id; }
    public String getClientIp()                { return clientIp; }
    public String getRequestUri()              { return requestUri; }
    public String getRequestPayload()          { return requestPayload; }
    public Classification getClassification()  { return classification; }
    public double getConfidenceScore()         { return confidenceScore; }
    public String getAttackType()              { return attackType; }
    public Long getMatchedPatternId()          { return matchedPatternId; }
    public ActionTaken getActionTaken()        { return actionTaken; }
    public LocalDateTime getClassifiedAt()     { return classifiedAt; }
    public long getResponseTimeMs()            { return responseTimeMs; }

    // ---- setters ----
    public void setId(Long id)                              { this.id = id; }
    public void setClientIp(String v)                       { this.clientIp = v; }
    public void setRequestUri(String v)                     { this.requestUri = v; }
    public void setRequestPayload(String v)                 { this.requestPayload = v; }
    public void setClassification(Classification v)         { this.classification = v; }
    public void setConfidenceScore(double v)                { this.confidenceScore = v; }
    public void setAttackType(String v)                     { this.attackType = v; }
    public void setMatchedPatternId(Long v)                 { this.matchedPatternId = v; }
    public void setActionTaken(ActionTaken v)               { this.actionTaken = v; }
    public void setClassifiedAt(LocalDateTime v)            { this.classifiedAt = v; }
    public void setResponseTimeMs(long v)                   { this.responseTimeMs = v; }

    // ---- builder ----
    public static Builder builder() { return new Builder(); }
    public static class Builder {
        private final ThreatClassification t = new ThreatClassification();
        public Builder clientIp(String v)              { t.clientIp = v;           return this; }
        public Builder requestUri(String v)            { t.requestUri = v;         return this; }
        public Builder requestPayload(String v)        { t.requestPayload = v;     return this; }
        public Builder classification(Classification v){ t.classification = v;     return this; }
        public Builder confidenceScore(double v)       { t.confidenceScore = v;    return this; }
        public Builder attackType(String v)            { t.attackType = v;         return this; }
        public Builder matchedPatternId(Long v)        { t.matchedPatternId = v;   return this; }
        public Builder actionTaken(ActionTaken v)      { t.actionTaken = v;        return this; }
        public Builder responseTimeMs(long v)          { t.responseTimeMs = v;     return this; }
        public ThreatClassification build()            { return t; }
    }
}
