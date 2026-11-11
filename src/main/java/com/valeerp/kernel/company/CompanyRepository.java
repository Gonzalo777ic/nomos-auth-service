package com.valeerp.kernel.company;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CompanyRepository extends JpaRepository<Company, Long> {

    boolean existsByLegalNameIgnoreCase(String legalName);

    Optional<Company> findByLegalNameIgnoreCase(String legalName);
}
