package com.valeerp.hr;

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
import java.time.LocalDate;

/**
 * Libro de ausencias. Nunca se borra ni se oculta con soft-delete.
 * Aprobación, cierre y anulación solo por transición de estado.
 */
@Entity
@Table(name = "hr_absences")
public class Absence {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "employee_id", nullable = false)
    private Long employeeId;

    @Column(name = "company_id", nullable = false)
    private Long companyId;

    @Enumerated(EnumType.STRING)
    @Column(name = "absence_type", nullable = false, length = 32)
    private AbsenceType absenceType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private AbsenceStatus status;

    @Column(name = "starts_on", nullable = false)
    private LocalDate startsOn;

    @Column(name = "ends_on", nullable = false)
    private LocalDate endsOn;

    @Column(length = 500)
    private String reason;

    @Column(name = "registered_at", nullable = false)
    private Instant registeredAt;

    @Column(name = "approved_at")
    private Instant approvedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "cancelled_at")
    private Instant cancelledAt;

    @Column(name = "cancelled_by", length = 120)
    private String cancelledBy;

    @Column(name = "cancel_reason", length = 255)
    private String cancelReason;

    protected Absence() {
    }

    public static Absence draft(
            Long employeeId,
            Long companyId,
            AbsenceType absenceType,
            LocalDate startsOn,
            LocalDate endsOn,
            String reason,
            Instant when
    ) {
        if (employeeId == null) {
            throw new DomainException("El empleado de la ausencia es obligatorio");
        }
        if (companyId == null) {
            throw new DomainException("La compañía de la ausencia es obligatoria");
        }
        if (absenceType == null) {
            throw new DomainException("El tipo de ausencia es obligatorio");
        }
        if (startsOn == null || endsOn == null) {
            throw new DomainException("El periodo de ausencia es obligatorio");
        }
        if (endsOn.isBefore(startsOn)) {
            throw new DomainException("La fecha de fin no puede ser anterior al inicio");
        }
        if (when == null) {
            throw new DomainException("El instante de registro es obligatorio");
        }
        Absence absence = new Absence();
        absence.employeeId = employeeId;
        absence.companyId = companyId;
        absence.absenceType = absenceType;
        absence.startsOn = startsOn;
        absence.endsOn = endsOn;
        absence.reason = reason == null || reason.isBlank() ? null : reason.trim();
        absence.status = AbsenceStatus.DRAFT;
        absence.registeredAt = when;
        return absence;
    }

    public void approve(Instant when) {
        if (status != AbsenceStatus.DRAFT) {
            throw new DomainException("Solo una ausencia DRAFT puede aprobarse");
        }
        if (when == null) {
            throw new DomainException("El instante de aprobación es obligatorio");
        }
        this.status = AbsenceStatus.APPROVED;
        this.approvedAt = when;
    }

    public void complete(Instant when) {
        if (status != AbsenceStatus.APPROVED) {
            throw new DomainException("Solo una ausencia APPROVED puede completarse");
        }
        if (when == null) {
            throw new DomainException("El instante de cierre es obligatorio");
        }
        this.status = AbsenceStatus.COMPLETED;
        this.completedAt = when;
    }

    public void cancel(String actor, Instant when, String reason) {
        if (status == AbsenceStatus.COMPLETED || status == AbsenceStatus.CANCELLED) {
            throw new DomainException("No se puede anular una ausencia " + status);
        }
        if (when == null) {
            throw new DomainException("El instante de anulación es obligatorio");
        }
        this.status = AbsenceStatus.CANCELLED;
        this.cancelledAt = when;
        this.cancelledBy = actor == null || actor.isBlank() ? "sistema" : actor.trim();
        this.cancelReason = reason == null || reason.isBlank() ? "Anulación de ausencia" : reason.trim();
    }

    public Long getId() {
        return id;
    }

    public Long getEmployeeId() {
        return employeeId;
    }

    public Long getCompanyId() {
        return companyId;
    }

    public AbsenceType getAbsenceType() {
        return absenceType;
    }

    public AbsenceStatus getStatus() {
        return status;
    }

    public LocalDate getStartsOn() {
        return startsOn;
    }

    public LocalDate getEndsOn() {
        return endsOn;
    }

    public String getReason() {
        return reason;
    }

    public Instant getRegisteredAt() {
        return registeredAt;
    }

    public Instant getApprovedAt() {
        return approvedAt;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public Instant getCancelledAt() {
        return cancelledAt;
    }

    public String getCancelledBy() {
        return cancelledBy;
    }

    public String getCancelReason() {
        return cancelReason;
    }
}
