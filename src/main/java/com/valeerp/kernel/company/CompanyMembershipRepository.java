package com.valeerp.kernel.company;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CompanyMembershipRepository extends JpaRepository<CompanyMembership, Long> {

    List<CompanyMembership> findByCompanyId(Long companyId);

    List<CompanyMembership> findByUserId(Long userId);

    Optional<CompanyMembership> findByCompanyIdAndUserId(Long companyId, Long userId);

    boolean existsByCompanyIdAndUserId(Long companyId, Long userId);
}
