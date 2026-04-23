package com.cybersec.tip.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "ioc_indicators", indexes = {
    @Index(name = "idx_ioc_value", columnList = "indicator_value"),
    @Index(name = "idx_ioc_type",  columnList = "indicator_type")
})
public class IocIndicator {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "indicator_type", nullable = false)
    private IocType indicatorType;

    @Column(name = "indicator_value", nullable = false, length = 500) private String indicatorValue;
    @Column(name = "threat_score",    nullable = false)               private int threatScore;
    @Column(name = "source_feed",     length = 100)                   private String sourceFeed;
    @Column(length = 500)                                             private String description;
    @Column(name = "tags", length = 300)                              private String tags;

    @Enumerated(EnumType.STRING) @Column(nullable = false)
    private IocStatus status = IocStatus.ACTIVE;

    @Column(name = "first_seen") private LocalDateTime firstSeen;
    @Column(name = "last_seen")  private LocalDateTime lastSeen = LocalDateTime.now();
    @Column(name = "expiry_date")private LocalDateTime expiryDate;

    public enum IocType   { IP, DOMAIN, URL, FILE_HASH, EMAIL }
    public enum IocStatus { ACTIVE, EXPIRED, WHITELISTED }

    public Long getId()             { return id; }
    public IocType getIndicatorType()   { return indicatorType; }
    public String getIndicatorValue()   { return indicatorValue; }
    public int getThreatScore()     { return threatScore; }
    public String getSourceFeed()   { return sourceFeed; }
    public String getDescription()  { return description; }
    public String getTags()         { return tags; }
    public IocStatus getStatus()    { return status; }
    public LocalDateTime getFirstSeen()  { return firstSeen; }
    public LocalDateTime getLastSeen()   { return lastSeen; }
    public LocalDateTime getExpiryDate() { return expiryDate; }

    public void setStatus(IocStatus v)   { this.status = v; }
    public void setThreatScore(int v)    { this.threatScore = v; }
    public void setLastSeen(LocalDateTime v) { this.lastSeen = v; }

    public static Builder builder() { return new Builder(); }
    public static class Builder {
        private final IocIndicator i = new IocIndicator();
        public Builder indicatorType(IocType v)   { i.indicatorType = v;   return this; }
        public Builder indicatorValue(String v)   { i.indicatorValue = v;  return this; }
        public Builder threatScore(int v)         { i.threatScore = v;     return this; }
        public Builder sourceFeed(String v)       { i.sourceFeed = v;      return this; }
        public Builder description(String v)      { i.description = v;     return this; }
        public Builder tags(String v)             { i.tags = v;            return this; }
        public Builder status(IocStatus v)        { i.status = v;          return this; }
        public Builder firstSeen(LocalDateTime v) { i.firstSeen = v;       return this; }
        public Builder lastSeen(LocalDateTime v)  { i.lastSeen = v;        return this; }
        public IocIndicator build()               { return i; }
    }
}
