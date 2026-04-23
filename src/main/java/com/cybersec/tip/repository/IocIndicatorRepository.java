package com.cybersec.tip.repository;
import com.cybersec.tip.model.IocIndicator;
import com.cybersec.tip.model.IocIndicator.IocStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface IocIndicatorRepository extends JpaRepository<IocIndicator, Long> {
    @Query("SELECT i FROM IocIndicator i WHERE i.indicatorValue = :val AND i.status = 'ACTIVE'")
    Optional<IocIndicator> findActiveByIndicatorValue(@Param("val") String value);
    boolean existsByIndicatorValue(String value);
    long countByStatus(IocStatus status);
    @Query("SELECT i FROM IocIndicator i WHERE i.status = 'ACTIVE' ORDER BY i.threatScore DESC LIMIT :n")
    List<IocIndicator> findTopThreatsByScore(@Param("n") int n);
}
