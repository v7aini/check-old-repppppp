package com.cybersec.ids.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "traffic_logs", indexes = {
    @Index(name = "idx_traffic_ip",   columnList = "client_ip"),
    @Index(name = "idx_traffic_time", columnList = "request_time")
})
public class TrafficLog {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_ip",    nullable = false, length = 45)  private String clientIp;
    @Column(name = "request_uri",  nullable = false, length = 500) private String requestUri;
    @Column(name = "query_string", length = 1000)                  private String queryString;
    @Column(name = "http_method",  length = 10)                    private String method;
    @Column(name = "user_agent",   length = 500)                   private String userAgent;
    @Column(name = "status_code")                                  private Integer statusCode;
    @Column(name = "payload_size")                                 private Integer payloadSize;
    @Column(name = "request_time", nullable = false)
    private LocalDateTime requestTime = LocalDateTime.now();

    public Long getId()            { return id; }
    public String getClientIp()    { return clientIp; }
    public String getRequestUri()  { return requestUri; }
    public String getQueryString() { return queryString; }
    public String getMethod()      { return method; }
    public String getUserAgent()   { return userAgent; }
    public Integer getStatusCode() { return statusCode; }
    public Integer getPayloadSize() { return payloadSize; }
    public LocalDateTime getRequestTime() { return requestTime; }

    public void setClientIp(String v)    { this.clientIp = v; }
    public void setRequestUri(String v)  { this.requestUri = v; }
    public void setQueryString(String v) { this.queryString = v; }
    public void setMethod(String v)      { this.method = v; }
    public void setUserAgent(String v)   { this.userAgent = v; }
    public void setStatusCode(Integer v) { this.statusCode = v; }
    public void setPayloadSize(Integer v) { this.payloadSize = v; }
    public void setRequestTime(LocalDateTime v) { this.requestTime = v; }

    public static Builder builder() { return new Builder(); }
    public static class Builder {
        private final TrafficLog t = new TrafficLog();
        public Builder clientIp(String v)    { t.clientIp = v;    return this; }
        public Builder requestUri(String v)  { t.requestUri = v;  return this; }
        public Builder queryString(String v) { t.queryString = v; return this; }
        public Builder method(String v)      { t.method = v;      return this; }
        public Builder userAgent(String v)   { t.userAgent = v;   return this; }
        public Builder payloadSize(Integer v){ t.payloadSize = v; return this; }
        public TrafficLog build()            { return t; }
    }
}
