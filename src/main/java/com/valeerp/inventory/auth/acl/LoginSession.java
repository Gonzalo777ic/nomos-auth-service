package com.valeerp.inventory.auth.acl;

import com.valeerp.kernel.DomainException;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * Libro de auditoría de login/sesión. Nunca se borra ni se oculta con soft-delete.
 * La anulación cambia el estado a VOIDED (reverso documentado).
 */
@Entity
@Table(name = "login_sessions")
public class LoginSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(nullable = false, length = 180)
    private String username;

    @Column(name = "started_at", nullable = false)
    private Instant startedAt;

    @Column(name = "ended_at")
    private Instant endedAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private SessionStatus status;

    @Column(name = "client_ip", length = 64)
    private String clientIp;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "voided_at")
    private Instant voidedAt;

    @Column(name = "voided_by", length = 120)
    private String voidedBy;

    @Column(name = "void_reason", length = 255)
    private String voidReason;

    protected LoginSession() {
    }

    public static LoginSession open(Long userId, String username, Instant when, String clientIp, String userAgent) {
        if (userId == null) {
            throw new DomainException("El usuario de la sesión es obligatorio");
        }
        if (username == null || username.isBlank()) {
            throw new DomainException("El username de la sesión es obligatorio");
        }
        if (when == null) {
            throw new DomainException("El instante de apertura es obligatorio");
        }
        LoginSession session = new LoginSession();
        session.userId = userId;
        session.username = username.trim();
        session.startedAt = when;
        session.status = SessionStatus.ACTIVE;
        session.clientIp = blankToNull(clientIp);
        session.userAgent = blankToNull(userAgent);
        return session;
    }

    public void voidSession(String actor, Instant when, String reason) {
        if (status == SessionStatus.VOIDED) {
            throw new DomainException("La sesión ya fue anulada");
        }
        if (when == null) {
            throw new DomainException("El instante de anulación es obligatorio");
        }
        this.status = SessionStatus.VOIDED;
        this.voidedAt = when;
        this.endedAt = when;
        this.voidedBy = actor == null || actor.isBlank() ? "sistema" : actor.trim();
        this.voidReason = reason == null || reason.isBlank() ? "Anulación de sesión" : reason.trim();
    }

    public void close(Instant when) {
        if (status != SessionStatus.ACTIVE) {
            throw new DomainException("Solo se puede cerrar una sesión ACTIVE");
        }
        if (when == null) {
            throw new DomainException("El instante de cierre es obligatorio");
        }
        this.endedAt = when;
    }

    public Long getId() {
        return id;
    }

    public Long getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public Instant getEndedAt() {
        return endedAt;
    }

    public SessionStatus getStatus() {
        return status;
    }

    public String getClientIp() {
        return clientIp;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public Instant getVoidedAt() {
        return voidedAt;
    }

    public String getVoidedBy() {
        return voidedBy;
    }

    public String getVoidReason() {
        return voidReason;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
