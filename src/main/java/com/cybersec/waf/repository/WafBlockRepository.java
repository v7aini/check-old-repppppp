package com.cybersec.waf.repository;
import com.cybersec.waf.model.WafBlock;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface WafBlockRepository extends JpaRepository<WafBlock, Long> {
    long countByBlockedAtAfter(LocalDateTime since);
    List<WafBlock> findTop100ByOrderByBlockedAtDesc();
    @Query("SELECT w.attackType, COUNT(w) FROM WafBlock w WHERE w.blockedAt > :since GROUP BY w.attackType ORDER BY COUNT(w) DESC")
    List<Object[]> countByTypeSince(@Param("since") LocalDateTime since);
}
