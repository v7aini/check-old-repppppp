package com.cybersec.ids.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Persistent record of known attack patterns learned by the trained ML models.
 * Used to quickly identify whether an incoming request matches a previously-seen
 * attack type – enabling early detection and faster response times.
 */
@Entity
@Table(name = "attack_patterns", indexes = {
    @Index(name = "idx_pattern_type",  columnList = "attack_type"),
    @Index(name = "idx_pattern_sig",   columnList = "signature_hash")
})
public class AttackPattern {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "attack_type", nullable = false, length = 60)
    private String attackType;

    @Column(name = "signature_hash", nullable = false, length = 64, unique = true)
    private String signatureHash;

    @Column(name = "sample_payload", length = 1000)
    private String samplePayload;

    @Column(name = "first_seen", nullable = false)
    private LocalDateTime firstSeen = LocalDateTime.now();

    @Column(name = "last_seen", nullable = false)
    private LocalDateTime lastSeen = LocalDateTime.now();

    @Column(name = "hit_count", nullable = false)
    private long hitCount = 1L;

    @Column(name = "avg_threat_score")
    private double avgThreatScore = 0.0;

    @Column(name = "auto_block_enabled", nullable = false)
    private boolean autoBlockEnabled = false;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 15)
    private ThreatLevel threatLevel = ThreatLevel.SUSPICIOUS;

    public enum ThreatLevel { SAFE, SUSPICIOUS, MALICIOUS }

    // ---- helpers ----
    public void recordHit(double score) {
        hitCount++;
        lastSeen = LocalDateTime.now();
        avgThreatScore = ((avgThreatScore * (hitCount - 1)) + score) / hitCount;
        if (avgThreatScore >= 0.85) {
            threatLevel = ThreatLevel.MALICIOUS;
            autoBlockEnabled = true;
        } else if (avgThreatScore >= 0.50) {
            threatLevel = ThreatLevel.SUSPICIOUS;
        }
    }

    // ---- getters ----
    public Long getId()                   { return id; }
    public String getAttackType()         { return attackType; }
    public String getSignatureHash()      { return signatureHash; }
    public String getSamplePayload()      { return samplePayload; }
    public LocalDateTime getFirstSeen()   { return firstSeen; }
    public LocalDateTime getLastSeen()    { return lastSeen; }
    public long getHitCount()             { return hitCount; }
    public double getAvgThreatScore()     { return avgThreatScore; }
    public boolean isAutoBlockEnabled()   { return autoBlockEnabled; }
    public ThreatLevel getThreatLevel()   { return threatLevel; }

    // ---- setters ----
    public void setId(Long id)                        { this.id = id; }
    public void setAttackType(String v)               { this.attackType = v; }
    public void setSignatureHash(String v)            { this.signatureHash = v; }
    public void setSamplePayload(String v)            { this.samplePayload = v; }
    public void setFirstSeen(LocalDateTime v)         { this.firstSeen = v; }
    public void setLastSeen(LocalDateTime v)          { this.lastSeen = v; }
    public void setHitCount(long v)                   { this.hitCount = v; }
    public void setAvgThreatScore(double v)           { this.avgThreatScore = v; }
    public void setAutoBlockEnabled(boolean v)        { this.autoBlockEnabled = v; }
    public void setThreatLevel(ThreatLevel v)         { this.threatLevel = v; }

    // ---- builder ----
    public static Builder builder() { return new Builder(); }
    public static class Builder {
        private final AttackPattern p = new AttackPattern();
        public Builder attackType(String v)      { p.attackType = v;      return this; }
        public Builder signatureHash(String v)   { p.signatureHash = v;   return this; }
        public Builder samplePayload(String v)   { p.samplePayload = v;   return this; }
        public Builder threatLevel(ThreatLevel v){ p.threatLevel = v;     return this; }
        public Builder avgThreatScore(double v)  { p.avgThreatScore = v;  return this; }
        public Builder autoBlockEnabled(boolean v){ p.autoBlockEnabled = v; return this; }
        public AttackPattern build()             { return p; }
    }
}
