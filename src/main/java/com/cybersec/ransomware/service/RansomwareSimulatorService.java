package com.cybersec.ransomware.service;

import com.cybersec.ransomware.ml.RansomwareRandomForest;
import com.cybersec.ransomware.model.RansomwareAlert;
import com.cybersec.ransomware.model.RansomwareAlertRepository;
import com.cybersec.telegram.TelegramAlertService;
import com.cybersec.shared.blockchain.BlockchainService;
import com.cybersec.shared.policy.SecurityPolicyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.Map;

@Service
public class RansomwareSimulatorService {
    private static final Logger logger = LoggerFactory.getLogger(RansomwareSimulatorService.class);

    @Autowired
    private RansomwareRandomForest mlModel;

    @Autowired
    private RansomwareAlertRepository alertRepository;

    @Autowired
    private TelegramAlertService telegramService;

    @Autowired
    private BlockchainService blockchainService;

    @Autowired
    private SecurityPolicyService policyService;

    public Map<String, Object> simulateTraffic(double packetVar, double entropy, double fileAccess, double duration, double freq) {
        double[] distribution = mlModel.getDistribution(packetVar, entropy, fileAccess, duration, freq);
        double ransomwareProb = distribution[1];
        
        Map<String, Double> explanation = mlModel.explainPrediction(packetVar, entropy, fileAccess, duration, freq);
        
        Map<String, Object> result = new HashMap<>();
        result.put("probability", ransomwareProb);
        result.put("classification", ransomwareProb > 0.5 ? "RANSOMWARE" : "NORMAL");
        result.put("explanation", explanation);
        
        if (ransomwareProb > 0.5) {
            logger.warn("RANSOMWARE DETECTED! Probability: {}", ransomwareProb);
            String sourceIp = "192.168.1." + (int)(Math.random() * 254);
            
            RansomwareAlert alert = new RansomwareAlert(
                sourceIp,
                "/data/sensitive/financial_records.enc",
                ransomwareProb,
                "ML_ENSEMBLE",
                "BLOCKED"
            );
            
            Map<String, Double> features = new HashMap<>();
            features.put("packetVar", packetVar);
            features.put("entropy", entropy);
            features.put("fileAccess", fileAccess);
            features.put("duration", duration);
            features.put("freq", freq);
            
            alert.setFeatures(features.toString());
            try {
                String expJson = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(explanation);
                alert.setExplanation(expJson);
                
                // --- BLOCKCHAIN INTEGRITY ---
                blockchainService.addAlertToChain(sourceIp + "|" + ransomwareProb + "|" + expJson);
            } catch (Exception e) {
                alert.setExplanation(explanation.toString());
            }
            alertRepository.save(alert);

            // --- AUTOMATED POLICY ENFORCEMENT ---
            policyService.enforcePolicy(sourceIp, ransomwareProb, "ML_ENSEMBLE_DETECTION");
            
            telegramService.sendCustomMessage("🚨 [Ransomware Simulation Alert] 🚨\n" +
                "Threat Score: " + String.format("%.2f", ransomwareProb * 100) + "%\n" +
                "Blockchain: Hashed & Verified\n" +
                "Primary Driver: " + explanation.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey)
                    .orElse("Mixed") + "\n" +
                "Action: " + (ransomwareProb > 0.8 ? "IP BLOCKED" : "IP MONITORED"));
        }
        
        return result;
    }

    /**
     * Phase 4: Adversarial Attack Simulation
     * Generates a "Mutated" version of a ransomware payload that tries to evade the ML model
     * by minimizing the threat score while maintaining malicious intent.
     */
    public Map<String, Object> generateAdversarialPayload(double pVar, double ent, double fAcc, double dur, double freq) {
        double currentProb = mlModel.getDistribution(pVar, ent, fAcc, dur, freq)[1];
        
        // Strategy: Iteratively reduce the features that contribute most to the threat score
        double bestVar = pVar, bestEnt = ent, bestFreq = freq;
        double minProb = currentProb;

        // Simulate "Evasion Mutation" (Adversarial perturbation)
        for (int i = 0; i < 10; i++) {
            double testVar = bestVar * 0.9; // Reduce burstiness
            double testEnt = bestEnt * 0.95; // Add noise to mask entropy
            double testFreq = bestFreq * 0.85; // Slow down requests
            
            double testProb = mlModel.getDistribution(testVar, testEnt, fAcc, dur, testFreq)[1];
            if (testProb < minProb) {
                minProb = testProb;
                bestVar = testVar;
                bestEnt = testEnt;
                bestFreq = testFreq;
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("originalProbability", currentProb);
        result.put("adversarialProbability", minProb);
        result.put("evasionSuccess", minProb < 0.5 && currentProb >= 0.5);
        result.put("mutatedFeatures", Map.of(
            "packetVar", bestVar,
            "entropy", bestEnt,
            "freq", bestFreq
        ));
        result.put("status", minProb < 0.5 ? "EVADED" : "CAUGHT");
        
        return result;
    }
}
