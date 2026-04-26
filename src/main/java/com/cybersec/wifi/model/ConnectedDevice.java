package com.cybersec.wifi.model;

public class ConnectedDevice {
    private String ipAddress;
    private String macAddress;
    private String hostname;
    private String manufacturer;
    private boolean isSelf;

    public ConnectedDevice() {}

    public ConnectedDevice(String ipAddress, String macAddress, String hostname, String manufacturer, boolean isSelf) {
        this.ipAddress = ipAddress;
        this.macAddress = macAddress;
        this.hostname = hostname;
        this.manufacturer = manufacturer;
        this.isSelf = isSelf;
    }

    // Getters and Setters
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getMacAddress() { return macAddress; }
    public void setMacAddress(String macAddress) { this.macAddress = macAddress; }

    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }

    public String getManufacturer() { return manufacturer; }
    public void setManufacturer(String manufacturer) { this.manufacturer = manufacturer; }

    public boolean isSelf() { return isSelf; }
    public void setSelf(boolean self) { isSelf = self; }
}
