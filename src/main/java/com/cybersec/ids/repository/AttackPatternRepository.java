package com.cybersec.ids.repository;

import com.cybersec.ids.model.AttackPattern;
import com.cybersec.ids.model.AttackPattern.ThreatLevel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AttackPatternRepository extends JpaRepository<AttackPattern, Long> {

    Optional<AttackPattern> findBySignatureHash(String signatureHash);

    List<AttackPattern> findByAttackType(String attackType);

    List<AttackPattern> findByThreatLevel(ThreatLevel threatLevel);

    List<AttackPattern> findByAutoBlockEnabledTrue();

    @Query("SELECT p FROM AttackPattern p ORDER BY p.hitCount DESC")
    List<AttackPattern> findTopPatterns();

    @Query("SELECT p FROM AttackPattern p WHERE p.hitCount >= :minHits ORDER BY p.lastSeen DESC")
    List<AttackPattern> findFrequentPatterns(@Param("minHits") long minHits);

    @Query("SELECT p.attackType, COUNT(p), SUM(p.hitCount) FROM AttackPattern p GROUP BY p.attackType ORDER BY SUM(p.hitCount) DESC")
    List<Object[]> getPatternSummary();

    long countByThreatLevel(ThreatLevel level);
}
