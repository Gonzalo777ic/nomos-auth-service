package com.valeerp.hr;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface EmployeeRepository extends JpaRepository<Employee, Long> {

    List<Employee> findByCompanyId(Long companyId);

    List<Employee> findByDepartmentId(Long departmentId);

    Optional<Employee> findByCompanyIdAndCodeIgnoreCase(Long companyId, String code);

    boolean existsByCompanyIdAndCodeIgnoreCase(Long companyId, String code);

    boolean existsByUserId(Long userId);
}
