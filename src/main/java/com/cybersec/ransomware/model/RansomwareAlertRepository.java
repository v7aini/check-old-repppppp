package com.cybersec.ransomware.model;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface RansomwareAlertRepository extends JpaRepository<RansomwareAlert, Long> {
    List<RansomwareAlert> findTop10ByOrderByTimestampDesc();
}
