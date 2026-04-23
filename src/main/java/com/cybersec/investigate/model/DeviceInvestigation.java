package com.cybersec.investigate.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "device_investigations")
public class DeviceInvestigation {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address",   nullable = false, length = 45) private String ipAddress;
    @Column(name = "mac_address",  length = 50)                   private String macAddress;
    @Column(name = "hostname",     length = 200)                  private String hostname;

    @Enumerated(EnumType.STRING) @Column(nullable = false)
    private InvestigationStatus status = InvestigationStatus.MONITORING;

    @Column(name = "reason",       length = 500) private String reason;
    @Column(name = "notes",        length = 2000) private String notes;
    @Column(name = "created_at")                 private LocalDateTime createdAt = LocalDateTime.now();
    @Column(name = "updated_at")                 private LocalDateTime updatedAt = LocalDateTime.now();
    @Column(name = "alert_count")                private int alertCount = 0;
    @Column(name = "packet_count")               private long packetCount = 0;
    @Column(name = "threat_score")               private int threatScore = 0;
    @Column(name = "telegram_notified")          private boolean telegramNotified = false;

    public enum InvestigationStatus { MONITORING, BLOCKED, WHITELISTED, RESOLVED }

    public Long getId()               { return id; }
    public String getIpAddress()      { return ipAddress; }
    public String getMacAddress()     { return macAddress; }
    public String getHostname()       { return hostname; }
    public InvestigationStatus getStatus() { return status; }
    public String getReason()         { return reason; }
    public String getNotes()          { return notes; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public int getAlertCount()        { return alertCount; }
    public long getPacketCount()      { return packetCount; }
    public int getThreatScore()       { return threatScore; }
    public boolean isTelegramNotified() { return telegramNotified; }

    public void setIpAddress(String v)     { this.ipAddress = v; }
    public void setMacAddress(String v)    { this.macAddress = v; }
    public void setHostname(String v)      { this.hostname = v; }
    public void setStatus(InvestigationStatus v) { this.status = v; }
    public void setReason(String v)        { this.reason = v; }
    public void setNotes(String v)         { this.notes = v; }
    public void setUpdatedAt(LocalDateTime v) { this.updatedAt = v; }
    public void setAlertCount(int v)       { this.alertCount = v; }
    public void setPacketCount(long v)     { this.packetCount = v; }
    public void setThreatScore(int v)      { this.threatScore = v; }
    public void setTelegramNotified(boolean v) { this.telegramNotified = v; }

    public static Builder builder() { return new Builder(); }
    public static class Builder {
        private final DeviceInvestigation d = new DeviceInvestigation();
        public Builder ipAddress(String v)    { d.ipAddress = v;  return this; }
        public Builder macAddress(String v)   { d.macAddress = v; return this; }
        public Builder hostname(String v)     { d.hostname = v;   return this; }
        public Builder status(InvestigationStatus v) { d.status = v; return this; }
        public Builder reason(String v)       { d.reason = v;     return this; }
        public Builder threatScore(int v)     { d.threatScore = v; return this; }
        public DeviceInvestigation build()    { return d; }
    }
}
