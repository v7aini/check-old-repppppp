package com.cybersec.waf.service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class RateLimiterService {
    private static final Logger log = LoggerFactory.getLogger(RateLimiterService.class);
    @Value("${waf.rate-limit.requests-per-minute:100}") private int requestsPerMinute;
    private final ConcurrentHashMap<String, AtomicInteger> buckets = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicInteger> strikes = new ConcurrentHashMap<>();

    public boolean isAllowed(String ip) {
        AtomicInteger t = buckets.computeIfAbsent(ip, k -> new AtomicInteger(requestsPerMinute));
        if (t.decrementAndGet() < 0) { t.set(0); strikes.computeIfAbsent(ip, k -> new AtomicInteger()).incrementAndGet(); return false; }
        return true;
    }
    public int getRemainingTokens(String ip) { AtomicInteger b = buckets.get(ip); return b != null ? Math.max(0,b.get()) : requestsPerMinute; }
    public int getStrikeCount(String ip)     { AtomicInteger s = strikes.get(ip); return s != null ? s.get() : 0; }
    public void clearStrikes(String ip)      { strikes.remove(ip); buckets.remove(ip); }
    @Scheduled(fixedDelay = 60_000)
    public void refill() { buckets.forEach((ip, b) -> b.set(requestsPerMinute)); }
}
