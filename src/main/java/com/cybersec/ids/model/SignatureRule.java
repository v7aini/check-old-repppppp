package com.cybersec.ids.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "signature_rules")
public class SignatureRule {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rule_name",     nullable = false, length = 100)  private String ruleName;
    @Column(name = "regex_pattern", nullable = false, length = 1000) private String regexPattern;
    @Column(name = "attack_type",   nullable = false, length = 50)   private String attackType;
    @Column(length = 50)                                              private String severity;
    @Column(length = 500)                                             private String description;
    @Column(nullable = false)                                         private boolean enabled = true;
    @Column(name = "created_at")    private LocalDateTime createdAt = LocalDateTime.now();
    @Column(name = "hit_count")     private long hitCount = 0L;

    public Long getId()             { return id; }
    public String getRuleName()     { return ruleName; }
    public String getRegexPattern() { return regexPattern; }
    public String getAttackType()   { return attackType; }
    public String getSeverity()     { return severity; }
    public String getDescription()  { return description; }
    public boolean isEnabled()      { return enabled; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public long getHitCount()       { return hitCount; }

    public void setEnabled(boolean v)      { this.enabled = v; }
    public void setHitCount(long v)        { this.hitCount = v; }
    public void setDescription(String v)   { this.description = v; }

    public static Builder builder() { return new Builder(); }
    public static class Builder {
        private final SignatureRule r = new SignatureRule();
        public Builder ruleName(String v)     { r.ruleName = v;     return this; }
        public Builder regexPattern(String v) { r.regexPattern = v; return this; }
        public Builder attackType(String v)   { r.attackType = v;   return this; }
        public Builder severity(String v)     { r.severity = v;     return this; }
        public Builder description(String v)  { r.description = v;  return this; }
        public Builder enabled(boolean v)     { r.enabled = v;      return this; }
        public SignatureRule build()           { return r; }
    }
}
