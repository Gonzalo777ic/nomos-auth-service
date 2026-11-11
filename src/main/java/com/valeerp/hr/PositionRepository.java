package com.valeerp.hr;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PositionRepository extends JpaRepository<Position, Long> {

    List<Position> findByCompanyId(Long companyId);

    Optional<Position> findByCompanyIdAndCodeIgnoreCase(Long companyId, String code);

    boolean existsByCompanyIdAndCodeIgnoreCase(Long companyId, String code);
}
