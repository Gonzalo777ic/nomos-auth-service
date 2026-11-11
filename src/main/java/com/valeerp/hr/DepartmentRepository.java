package com.valeerp.hr;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface DepartmentRepository extends JpaRepository<Department, Long> {

    List<Department> findByCompanyId(Long companyId);

    Optional<Department> findByCompanyIdAndCodeIgnoreCase(Long companyId, String code);

    boolean existsByCompanyIdAndCodeIgnoreCase(Long companyId, String code);
}
