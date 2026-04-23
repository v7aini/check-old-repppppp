package com.cybersec.waf.repository;
import com.cybersec.waf.model.IpBlockEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface IpBlocklistRepository extends JpaRepository<IpBlockEntry, Long> {
    @Query("SELECT e FROM IpBlockEntry e WHERE e.ipAddress = :ip AND e.active = true AND (e.expiresAt IS NULL OR e.expiresAt > CURRENT_TIMESTAMP)")
    Optional<IpBlockEntry> findActiveByIp(@Param("ip") String ip);
    List<IpBlockEntry> findByActiveTrue();
}
