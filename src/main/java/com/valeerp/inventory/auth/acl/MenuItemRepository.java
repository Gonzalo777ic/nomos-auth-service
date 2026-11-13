package com.valeerp.inventory.auth.acl;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface MenuItemRepository extends JpaRepository<MenuItem, Long> {

    Optional<MenuItem> findByKey(String key);

    List<MenuItem> findAllByOrderBySortOrderAscKeyAsc();

    boolean existsByKey(String key);
}
