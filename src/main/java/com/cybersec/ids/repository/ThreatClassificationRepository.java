package com.cybersec.ids.repository;

import com.cybersec.ids.model.ThreatClassification;
import com.cybersec.ids.model.ThreatClassification.Classification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface ThreatClassificationRepository extends JpaRepository<ThreatClassification, Long> {

    List<ThreatClassification> findByClientIpOrderByClassifiedAtDesc(String clientIp);

    List<ThreatClassification> findByClassificationOrderByClassifiedAtDesc(Classification classification);

    long countByClassification(Classification classification);

    long countByClassifiedAtAfter(LocalDateTime since);

    @Query("SELECT t FROM ThreatClassification t WHERE t.classifiedAt > :since ORDER BY t.classifiedAt DESC")
    List<ThreatClassification> findRecentClassifications(@Param("since") LocalDateTime since);

    @Query("SELECT t.classification, COUNT(t) FROM ThreatClassification t WHERE t.classifiedAt > :since GROUP BY t.classification")
    List<Object[]> countByClassificationSince(@Param("since") LocalDateTime since);

    @Query("SELECT t.attackType, COUNT(t) FROM ThreatClassification t WHERE t.classification <> :safeClass AND t.classifiedAt > :since GROUP BY t.attackType ORDER BY COUNT(t) DESC")
    List<Object[]> getTopAttackTypesSince(@Param("since") LocalDateTime since, @Param("safeClass") Classification safeClass);
}
