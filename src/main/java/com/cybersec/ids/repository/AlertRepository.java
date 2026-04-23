package com.cybersec.ids.repository;
import com.cybersec.ids.model.Alert;
import com.cybersec.ids.model.Alert.AlertStatus;
import com.cybersec.ids.model.Alert.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.*;

@Repository
public interface AlertRepository extends JpaRepository<Alert, Long> {
    @Query("SELECT a FROM Alert a ORDER BY a.detectedAt DESC LIMIT :n")
    List<Alert> findTopNByOrderByDetectedAtDesc(@Param("n") int n);
    List<Alert> findByStatusOrderByDetectedAtDesc(AlertStatus status);
    List<Alert> findBySourceIpOrderByDetectedAtDesc(String sourceIp);
    List<Alert> findByDetectedAtAfter(LocalDateTime since);
    long countByDetectedAtAfter(LocalDateTime since);
    long countBySeverity(Severity severity);
    List<Alert> findBySeverity(Severity severity);
    @Query("SELECT a.attackType, COUNT(a) FROM Alert a WHERE a.detectedAt > :since GROUP BY a.attackType ORDER BY COUNT(a) DESC")
    List<Object[]> countByAttackTypeRaw(@Param("since") LocalDateTime since);
    default Map<String, Long> countGroupedByAttackType() {
        Map<String, Long> result = new java.util.LinkedHashMap<>();
        for (Object[] row : countByAttackTypeRaw(LocalDateTime.now().minusDays(7)))
            result.put((String) row[0], (Long) row[1]);
        return result;
    }
}
