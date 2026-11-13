package com.valeerp.inventory.auth.acl;

import com.valeerp.inventory.auth.acl.dto.LoginSessionResponse;
import com.valeerp.inventory.auth.acl.dto.VoidSessionRequest;
import com.valeerp.kernel.Actors;
import com.valeerp.kernel.DomainException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

/**
 * Libro de auditoría de sesión: nunca borra filas; anula con estado VOIDED.
 */
@Service
public class SessionAuditService {

    private final LoginSessionRepository loginSessionRepository;

    public SessionAuditService(LoginSessionRepository loginSessionRepository) {
        this.loginSessionRepository = loginSessionRepository;
    }

    @Transactional
    public LoginSession openSession(Long userId, String username, String clientIp, String userAgent) {
        LoginSession session = LoginSession.open(userId, username, Instant.now(), clientIp, userAgent);
        return loginSessionRepository.save(session);
    }

    @Transactional(readOnly = true)
    public List<LoginSessionResponse> listSessions() {
        return loginSessionRepository.findAllByOrderByStartedAtDesc().stream()
                .map(LoginSessionResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<LoginSessionResponse> listByUser(Long userId) {
        if (userId == null) {
            throw new DomainException("El usuario es obligatorio");
        }
        return loginSessionRepository.findByUserIdOrderByStartedAtDesc(userId).stream()
                .map(LoginSessionResponse::from)
                .toList();
    }

    @Transactional
    public LoginSessionResponse voidSession(Long sessionId, VoidSessionRequest request) {
        LoginSession session = loginSessionRepository.findById(sessionId)
                .orElseThrow(() -> new DomainException("Sesión no encontrada"));
        String reason = request == null ? null : request.getReason();
        session.voidSession(Actors.current(), Instant.now(), reason);
        return LoginSessionResponse.from(loginSessionRepository.save(session));
    }
}
