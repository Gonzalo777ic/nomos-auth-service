package com.nomos.inventory.auth.acl;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LoginSessionRepository extends JpaRepository<LoginSession, Long> {

    List<LoginSession> findByUserIdOrderByStartedAtDesc(Long userId);

    List<LoginSession> findByStatusOrderByStartedAtDesc(SessionStatus status);

    List<LoginSession> findAllByOrderByStartedAtDesc();
}
