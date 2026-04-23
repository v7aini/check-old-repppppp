package com.cybersec.waf.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "ip_blocklist")
public class IpBlockEntry {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", nullable = false, length = 45) private String ipAddress;
    @Column(nullable = false, length = 300)                      private String reason;
    @Column(name = "blocked_at")                                 private LocalDateTime blockedAt;
    @Column(name = "expires_at")                                 private LocalDateTime expiresAt;
    @Column(nullable = false)                                    private boolean active = true;

    public Long getId()               { return id; }
    public String getIpAddress()      { return ipAddress; }
    public String getReason()         { return reason; }
    public LocalDateTime getBlockedAt()  { return blockedAt; }
    public LocalDateTime getExpiresAt()  { return expiresAt; }
    public boolean isActive()         { return active; }

    public void setIpAddress(String v)       { this.ipAddress = v; }
    public void setReason(String v)          { this.reason = v; }
    public void setBlockedAt(LocalDateTime v){ this.blockedAt = v; }
    public void setExpiresAt(LocalDateTime v){ this.expiresAt = v; }
    public void setActive(boolean v)         { this.active = v; }

    public static Builder builder() { return new Builder(); }
    public static class Builder {
        private final IpBlockEntry e = new IpBlockEntry();
        public Builder ipAddress(String v)       { e.ipAddress = v;  return this; }
        public Builder reason(String v)          { e.reason = v;     return this; }
        public Builder blockedAt(LocalDateTime v){ e.blockedAt = v;  return this; }
        public Builder expiresAt(LocalDateTime v){ e.expiresAt = v;  return this; }
        public Builder active(boolean v)         { e.active = v;     return this; }
        public IpBlockEntry build()              { return e; }
    }
}
