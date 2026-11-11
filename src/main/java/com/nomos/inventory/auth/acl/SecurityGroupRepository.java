package com.nomos.inventory.auth.acl;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SecurityGroupRepository extends JpaRepository<SecurityGroup, Long> {

    Optional<SecurityGroup> findByCode(String code);

    boolean existsByCode(String code);
}
