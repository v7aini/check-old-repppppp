package com.cybersec.waf.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "waf_blocks", indexes = {
    @Index(name = "idx_waf_ip",   columnList = "client_ip"),
    @Index(name = "idx_waf_time", columnList = "blocked_at")
})
public class WafBlock {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_ip",   nullable = false, length = 45) private String clientIp;
    @Column(name = "attack_type", nullable = false, length = 50) private String attackType;
    @Column(nullable = false, length = 500)                       private String detail;
    @Column(name = "request_uri", length = 500)                  private String requestUri;
    @Column(name = "http_method", length = 10)                   private String method;
    @Column(name = "status_code")                                 private int statusCode;
    @Column(name = "blocked_at",  nullable = false)
    private LocalDateTime blockedAt = LocalDateTime.now();

    public Long getId()            { return id; }
    public String getClientIp()    { return clientIp; }
    public String getAttackType()  { return attackType; }
    public String getDetail()      { return detail; }
    public String getRequestUri()  { return requestUri; }
    public String getMethod()      { return method; }
    public int getStatusCode()     { return statusCode; }
    public LocalDateTime getBlockedAt() { return blockedAt; }

    public static Builder builder() { return new Builder(); }
    public static class Builder {
        private final WafBlock b = new WafBlock();
        public Builder clientIp(String v)    { b.clientIp = v;    return this; }
        public Builder attackType(String v)  { b.attackType = v;  return this; }
        public Builder detail(String v)      { b.detail = v;      return this; }
        public Builder requestUri(String v)  { b.requestUri = v;  return this; }
        public Builder method(String v)      { b.method = v;      return this; }
        public Builder statusCode(int v)     { b.statusCode = v;  return this; }
        public Builder blockedAt(LocalDateTime v) { b.blockedAt = v; return this; }
        public WafBlock build()              { return b; }
    }
}
