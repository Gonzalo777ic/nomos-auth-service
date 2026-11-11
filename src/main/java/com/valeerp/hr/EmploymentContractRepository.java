package com.valeerp.hr;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface EmploymentContractRepository extends JpaRepository<EmploymentContract, Long> {

    List<EmploymentContract> findByEmployeeId(Long employeeId);

    List<EmploymentContract> findByCompanyId(Long companyId);

    List<EmploymentContract> findByEmployeeIdAndStatus(Long employeeId, ContractStatus status);
}
