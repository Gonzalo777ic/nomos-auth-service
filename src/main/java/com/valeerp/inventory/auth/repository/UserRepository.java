package com.valeerp.inventory.auth.repository;

import com.valeerp.inventory.auth.model.Role;
import com.valeerp.inventory.auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Optional<User> findByEmail(String email);

    Optional<User> findByAuth0Id(String auth0Id);

    List<User> findByRolesContaining(Role role);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    /**
     * Solo el id: {@code @SQLRestriction} ocultaría la entidad dada de baja.
     */
    @Query(value = "SELECT id FROM users WHERE lower(email) = lower(:email) AND deleted_at IS NOT NULL LIMIT 1",
            nativeQuery = true)
    Optional<Long> findRetiredIdByEmail(@Param("email") String email);

    @Query(value = "SELECT id FROM users WHERE id = :id AND deleted_at IS NOT NULL",
            nativeQuery = true)
    Optional<Long> findRetiredIdById(@Param("id") Long id);

    @Query(value = "SELECT email FROM users WHERE id = :id AND deleted_at IS NOT NULL",
            nativeQuery = true)
    Optional<String> findRetiredEmailById(@Param("id") Long id);

    @Query(value = "SELECT username FROM users WHERE id = :id AND deleted_at IS NOT NULL",
            nativeQuery = true)
    Optional<String> findRetiredUsernameById(@Param("id") Long id);

    /**
     * Reactivación a nivel SQL para bypass del {@code @SQLRestriction}.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(value = "UPDATE users SET deleted_at = NULL, deleted_by = NULL WHERE id = :id AND deleted_at IS NOT NULL",
            nativeQuery = true)
    int clearSoftDelete(@Param("id") Long id);
}
