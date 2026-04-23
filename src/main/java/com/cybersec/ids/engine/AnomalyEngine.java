package com.cybersec.ids.engine;
import com.cybersec.ids.model.TrafficLog;
import com.cybersec.ids.repository.TrafficLogRepository;
import com.cybersec.ids.service.AlertService;
import com.cybersec.shared.service.PythonMlClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Component
public class AnomalyEngine {
    private static final Logger log = LoggerFactory.getLogger(AnomalyEngine.class);
    private final AlertService alertService;
    private final TrafficLogRepository trafficRepo;
    private final PythonMlClient mlClient;
    
    @Value("${ids.anomaly.threshold:0.75}") private double threshold;
    private final ConcurrentHashMap<String, List<TrafficLog>> logHistory = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, List<Long>> windows = new ConcurrentHashMap<>();
    private double baseMean = 10.0, baseStd = 5.0;

    @Autowired
    public AnomalyEngine(@Lazy AlertService alertService,
                         TrafficLogRepository trafficRepo,
                         PythonMlClient mlClient) {
        this.alertService = alertService; 
        this.trafficRepo = trafficRepo;
        this.mlClient = mlClient;
    }

    public void analyse(TrafficLog tl) {
        String ip = tl.getClientIp(); long now = System.currentTimeMillis();
        
        // Update basic window for stats
        List<Long> w = windows.computeIfAbsent(ip, k -> Collections.synchronizedList(new ArrayList<>()));
        w.add(now); w.removeIf(t -> t < now - 60_000);
        
        // Update history for LSTM sequence
        List<TrafficLog> history = logHistory.computeIfAbsent(ip, k -> Collections.synchronizedList(new ArrayList<>()));
        history.add(tl);
        if (history.size() > 10) history.remove(0); // Keep last 10 requests for sequence

        // Get LSTM prediction if we have enough data
        double lstmScore = 0.0;
        if (history.size() >= 5) {
            List<double[]> sequence = history.stream().map(log -> new double[]{
                (double) windows.get(ip).size(),
                (double) (log.getPayloadSize() != null ? log.getPayloadSize() : 0),
                (double) log.getRequestUri().split("/").length,
                (double) (log.getQueryString() != null ? log.getQueryString().length() : 0)
            }).collect(Collectors.toList());
            
            Map<String, Object> prediction = mlClient.predictAnomaly(sequence);
            lstmScore = (Double) prediction.getOrDefault("anomaly_score", 0.0);
        }

        double statisticalScore = score(tl, w);
        double finalScore = Math.max(statisticalScore, lstmScore);

        if (finalScore >= threshold) {
            String method = finalScore == lstmScore ? "LSTM-RNN" : "STATISTICAL";
            alertService.fireAlert(ip, "ANOMALY_DETECTED",
                String.format("[%s] Anomaly score %.2f. Req/min:%d. URI:%s", method, finalScore, w.size(), tl.getRequestUri()),
                "IDS_ANOMALY", finalScore >= 0.9 ? "CRITICAL" : "HIGH");
        }
    }

    private double score(TrafficLog tl, List<Long> w) {
        double s = 0;
        double fz = (w.size() - baseMean) / Math.max(baseStd, 1.0);
        s += Math.min(1.0, Math.max(0.0, fz / 5.0)) * 0.45;
        int depth = tl.getRequestUri().split("/").length;
        s += (depth > 6 ? Math.min(1.0, (depth - 6) / 4.0) : 0.0) * 0.20;
        int qLen = tl.getQueryString() != null ? tl.getQueryString().length() : 0;
        s += (qLen > 200 ? Math.min(1.0, (qLen - 200) / 800.0) : 0.0) * 0.20;
        s += (tl.getUserAgent() == null || tl.getUserAgent().isBlank() ? 0.15 : 0.0);
        return Math.min(1.0, s);
    }

    @Scheduled(fixedDelay = 300_000)
    public void updateBaseline() {
        List<TrafficLog> recent = trafficRepo.findByRequestTimeAfter(LocalDateTime.now().minusMinutes(5));
        if (recent.isEmpty()) return;
        Map<String, Long> counts = new HashMap<>();
        for (TrafficLog tl : recent) counts.merge(tl.getClientIp(), 1L, Long::sum);
        double[] vals = counts.values().stream().mapToDouble(Long::doubleValue).toArray();
        baseMean = Arrays.stream(vals).average().orElse(10.0) / 5.0;
        double var = Arrays.stream(vals).map(c -> (c - baseMean * 5) * (c - baseMean * 5)).average().orElse(25.0);
        baseStd = Math.sqrt(var) / 5.0;
    }

    @Scheduled(fixedDelay = 300_000)
    public void evictStale() {
        long cut = System.currentTimeMillis() - 300_000;
        windows.entrySet().removeIf(e -> e.getValue().isEmpty() || Collections.max(e.getValue()) < cut);
    }
}
