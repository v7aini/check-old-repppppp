package com.cybersec.network.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "packet_records", indexes = {
    @Index(name = "idx_pkt_src",  columnList = "src_ip"),
    @Index(name = "idx_pkt_time", columnList = "captured_at")
})
public class PacketRecord {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "src_ip",       length = 45)  private String srcIp;
    @Column(name = "dst_ip",       length = 45)  private String dstIp;
    @Column(name = "src_port")                   private Integer srcPort;
    @Column(name = "dst_port")                   private Integer dstPort;
    @Column(name = "protocol",     length = 10)  private String protocol;
    @Column(name = "length")                     private Integer length;
    @Column(name = "info",         length = 500) private String info;
    @Column(name = "flags",        length = 50)  private String flags;
    @Column(name = "captured_at")               private LocalDateTime capturedAt = LocalDateTime.now();
    @Column(name = "interface_name", length = 30) private String interfaceName;
    @Column(name = "suspicious")                 private boolean suspicious = false;

    public Long getId()              { return id; }
    public String getSrcIp()         { return srcIp; }
    public String getDstIp()         { return dstIp; }
    public Integer getSrcPort()      { return srcPort; }
    public Integer getDstPort()      { return dstPort; }
    public String getProtocol()      { return protocol; }
    public Integer getLength()       { return length; }
    public String getInfo()          { return info; }
    public String getFlags()         { return flags; }
    public LocalDateTime getCapturedAt() { return capturedAt; }
    public String getInterfaceName() { return interfaceName; }
    public boolean isSuspicious()    { return suspicious; }

    public void setSrcIp(String v)       { this.srcIp = v; }
    public void setDstIp(String v)       { this.dstIp = v; }
    public void setSrcPort(Integer v)    { this.srcPort = v; }
    public void setDstPort(Integer v)    { this.dstPort = v; }
    public void setProtocol(String v)    { this.protocol = v; }
    public void setLength(Integer v)     { this.length = v; }
    public void setInfo(String v)        { this.info = v; }
    public void setFlags(String v)       { this.flags = v; }
    public void setCapturedAt(LocalDateTime v) { this.capturedAt = v; }
    public void setInterfaceName(String v)     { this.interfaceName = v; }
    public void setSuspicious(boolean v)       { this.suspicious = v; }

    public static Builder builder() { return new Builder(); }
    public static class Builder {
        private final PacketRecord p = new PacketRecord();
        public Builder srcIp(String v)     { p.srcIp = v;    return this; }
        public Builder dstIp(String v)     { p.dstIp = v;    return this; }
        public Builder srcPort(Integer v)  { p.srcPort = v;  return this; }
        public Builder dstPort(Integer v)  { p.dstPort = v;  return this; }
        public Builder protocol(String v)  { p.protocol = v; return this; }
        public Builder length(Integer v)   { p.length = v;   return this; }
        public Builder info(String v)      { p.info = v;     return this; }
        public Builder flags(String v)     { p.flags = v;    return this; }
        public Builder interfaceName(String v) { p.interfaceName = v; return this; }
        public Builder suspicious(boolean v)   { p.suspicious = v;   return this; }
        public PacketRecord build()        { return p; }
    }
}
