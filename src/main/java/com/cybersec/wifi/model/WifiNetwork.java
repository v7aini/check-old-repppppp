package com.cybersec.wifi.model;

public class WifiNetwork {
    private String ssid;
    private String bssid;
    private int signal;
    private String security;
    private int channel;
    private boolean rogue;

    public WifiNetwork() {}

    public WifiNetwork(String ssid, String bssid, int signal, String security, int channel, boolean rogue) {
        this.ssid = ssid;
        this.bssid = bssid;
        this.signal = signal;
        this.security = security;
        this.channel = channel;
        this.rogue = rogue;
    }

    public String getSsid() { return ssid; }
    public void setSsid(String ssid) { this.ssid = ssid; }
    public String getBssid() { return bssid; }
    public void setBssid(String bssid) { this.bssid = bssid; }
    public int getSignal() { return signal; }
    public void setSignal(int signal) { this.signal = signal; }
    public String getSecurity() { return security; }
    public void setSecurity(String security) { this.security = security; }
    public int getChannel() { return channel; }
    public void setChannel(int channel) { this.channel = channel; }
    public boolean isRogue() { return rogue; }
    public void setRogue(boolean rogue) { this.rogue = rogue; }
}
