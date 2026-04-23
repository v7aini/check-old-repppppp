package com.cybersec.ids.repository;
import com.cybersec.ids.model.TrafficLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface TrafficLogRepository extends JpaRepository<TrafficLog, Long> {
    List<TrafficLog> findByRequestTimeAfter(LocalDateTime since);
    long countByRequestTimeAfter(LocalDateTime since);
    @Query("SELECT HOUR(t.requestTime), COUNT(t) FROM TrafficLog t WHERE t.requestTime > :since GROUP BY HOUR(t.requestTime) ORDER BY HOUR(t.requestTime)")
    List<Object[]> countByHour(@Param("since") LocalDateTime since);
}
