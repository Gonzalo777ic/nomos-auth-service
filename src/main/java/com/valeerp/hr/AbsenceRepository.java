package com.valeerp.hr;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AbsenceRepository extends JpaRepository<Absence, Long> {

    List<Absence> findByEmployeeId(Long employeeId);

    List<Absence> findByCompanyId(Long companyId);
}
