package com.cybersec.network.repository;

import com.cybersec.network.model.PacketRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface PacketRepository extends JpaRepository<PacketRecord, Long> {
    List<PacketRecord> findTop200ByOrderByCapturedAtDesc();
    List<PacketRecord> findBySrcIpOrderByCapturedAtDesc(String ip);
    List<PacketRecord> findBySuspiciousTrue();
    long countByCapturedAtAfter(LocalDateTime since);

    @Query("SELECT p.protocol, COUNT(p) FROM PacketRecord p GROUP BY p.protocol ORDER BY COUNT(p) DESC")
    List<Object[]> countByProtocol();

    @Query("SELECT p.srcIp, COUNT(p) FROM PacketRecord p WHERE p.capturedAt > :since GROUP BY p.srcIp ORDER BY COUNT(p) DESC LIMIT 10")
    List<Object[]> topTalkers(@Param("since") LocalDateTime since);
}
