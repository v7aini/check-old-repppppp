package com.cybersec.investigate.repository;

import com.cybersec.investigate.model.DeviceInvestigation;
import com.cybersec.investigate.model.DeviceInvestigation.InvestigationStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface InvestigationRepository extends JpaRepository<DeviceInvestigation, Long> {
    Optional<DeviceInvestigation> findByIpAddress(String ip);
    List<DeviceInvestigation> findByStatusOrderByUpdatedAtDesc(InvestigationStatus status);
    List<DeviceInvestigation> findAllByOrderByUpdatedAtDesc();
    boolean existsByIpAddress(String ip);
}
