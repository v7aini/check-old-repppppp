package com.cybersec.ids.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "ids_alerts", indexes = {
    @Index(name = "idx_alert_ip",   columnList = "source_ip"),
    @Index(name = "idx_alert_time", columnList = "detected_at")
})
public class Alert {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "source_ip",    nullable = false, length = 45)  private String sourceIp;
    @Column(name = "attack_type",  nullable = false, length = 50)  private String attackType;
    @Column(nullable = false, length = 500)                         private String detail;
    @Column(name = "detected_by",  length = 30)                    private String detectedBy;

    @Enumerated(EnumType.STRING) @Column(nullable = false)
    private Severity severity = Severity.MEDIUM;

    @Enumerated(EnumType.STRING) @Column(nullable = false)
    private AlertStatus status = AlertStatus.OPEN;

    @Column(name = "detected_at",  nullable = false)
    private LocalDateTime detectedAt = LocalDateTime.now();

    @Column(name = "resolved_at")  private LocalDateTime resolvedAt;
    @Column(name = "request_uri",  length = 500) private String requestUri;
    @Column(name = "threat_score") private Integer threatScore;
    @Column(name = "notes",        length = 1000) private String notes;
    @Column(name = "country",      length = 100) private String country;
    @Column(name = "latitude")     private Double latitude;
    @Column(name = "longitude")    private Double longitude;

    public enum Severity    { LOW, MEDIUM, HIGH, CRITICAL }
    public enum AlertStatus { OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE }

    // Getters
    public Long getId()              { return id; }
    public String getSourceIp()      { return sourceIp; }
    public String getAttackType()    { return attackType; }
    public String getDetail()        { return detail; }
    public String getDetectedBy()    { return detectedBy; }
    public Severity getSeverity()    { return severity; }
    public AlertStatus getStatus()   { return status; }
    public LocalDateTime getDetectedAt()  { return detectedAt; }
    public LocalDateTime getResolvedAt()  { return resolvedAt; }
    public String getRequestUri()    { return requestUri; }
    public Integer getThreatScore()  { return threatScore; }
    public String getNotes()         { return notes; }
    public String getCountry()       { return country; }
    public Double getLatitude()      { return latitude; }
    public Double getLongitude()     { return longitude; }

    // Setters
    public void setId(Long id)                        { this.id = id; }
    public void setSourceIp(String v)                 { this.sourceIp = v; }
    public void setAttackType(String v)               { this.attackType = v; }
    public void setDetail(String v)                   { this.detail = v; }
    public void setDetectedBy(String v)               { this.detectedBy = v; }
    public void setSeverity(Severity v)               { this.severity = v; }
    public void setStatus(AlertStatus v)              { this.status = v; }
    public void setDetectedAt(LocalDateTime v)        { this.detectedAt = v; }
    public void setResolvedAt(LocalDateTime v)        { this.resolvedAt = v; }
    public void setRequestUri(String v)               { this.requestUri = v; }
    public void setThreatScore(Integer v)             { this.threatScore = v; }
    public void setNotes(String v)                    { this.notes = v; }
    public void setCountry(String v)                  { this.country = v; }
    public void setLatitude(Double v)                 { this.latitude = v; }
    public void setLongitude(Double v)                { this.longitude = v; }

    // Builder pattern
    public static Builder builder() { return new Builder(); }
    public static class Builder {
        private final Alert a = new Alert();
        public Builder sourceIp(String v)          { a.sourceIp = v;    return this; }
        public Builder attackType(String v)        { a.attackType = v;  return this; }
        public Builder detail(String v)            { a.detail = v;      return this; }
        public Builder detectedBy(String v)        { a.detectedBy = v;  return this; }
        public Builder severity(Severity v)        { a.severity = v;    return this; }
        public Builder status(AlertStatus v)       { a.status = v;      return this; }
        public Builder detectedAt(LocalDateTime v) { a.detectedAt = v;  return this; }
        public Builder threatScore(Integer v)      { a.threatScore = v; return this; }
        public Builder requestUri(String v)        { a.requestUri = v;  return this; }
        public Builder notes(String v)             { a.notes = v;       return this; }
        public Builder country(String v)           { a.country = v;     return this; }
        public Builder latitude(Double v)          { a.latitude = v;    return this; }
        public Builder longitude(Double v)         { a.longitude = v;   return this; }
        public Alert build() { return a; }
    }
}
