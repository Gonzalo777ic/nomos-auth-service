package com.valeerp.hr;

import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.Money;
import jakarta.persistence.AttributeOverride;
import jakarta.persistence.AttributeOverrides;
import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
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
 * Libro de contrato laboral. Nunca se borra ni se oculta con soft-delete.
 * Cierre y anulación solo por transición de estado.
 */
@Entity
@Table(name = "hr_employment_contracts")
public class EmploymentContract {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "employee_id", nullable = false)
    private Long employeeId;

    @Column(name = "company_id", nullable = false)
    private Long companyId;

    @Enumerated(EnumType.STRING)
    @Column(name = "contract_type", nullable = false, length = 32)
    private ContractType contractType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ContractStatus status;

    @Column(name = "starts_on", nullable = false)
    private LocalDate startsOn;

    @Column(name = "ends_on")
    private LocalDate endsOn;

    @Embedded
    @AttributeOverrides({
            @AttributeOverride(name = "amount", column = @Column(name = "wage_amount", nullable = false, precision = 19, scale = 2)),
            @AttributeOverride(name = "currencyCode", column = @Column(name = "wage_currency", nullable = false, length = 3))
    })
    private Money wage;

    @Column(name = "registered_at", nullable = false)
    private Instant registeredAt;

    @Column(name = "activated_at")
    private Instant activatedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "cancelled_at")
    private Instant cancelledAt;

    @Column(name = "cancelled_by", length = 120)
    private String cancelledBy;

    @Column(name = "cancel_reason", length = 255)
    private String cancelReason;

    protected EmploymentContract() {
    }

    public static EmploymentContract draft(
            Long employeeId,
            Long companyId,
            ContractType contractType,
            LocalDate startsOn,
            LocalDate endsOn,
            Money wage,
            Instant when
    ) {
        if (employeeId == null) {
            throw new DomainException("El empleado del contrato es obligatorio");
        }
        if (companyId == null) {
            throw new DomainException("La compañía del contrato es obligatoria");
        }
        if (contractType == null) {
            throw new DomainException("El tipo de contrato es obligatorio");
        }
        if (startsOn == null) {
            throw new DomainException("La fecha de inicio del contrato es obligatoria");
        }
        if (wage == null) {
            throw new DomainException("La remuneración del contrato es obligatoria");
        }
        if (when == null) {
            throw new DomainException("El instante de registro es obligatorio");
        }
        if (endsOn != null && endsOn.isBefore(startsOn)) {
            throw new DomainException("La fecha de fin no puede ser anterior al inicio");
        }
        EmploymentContract contract = new EmploymentContract();
        contract.employeeId = employeeId;
        contract.companyId = companyId;
        contract.contractType = contractType;
        contract.startsOn = startsOn;
        contract.endsOn = endsOn;
        contract.wage = wage;
        contract.status = ContractStatus.DRAFT;
        contract.registeredAt = when;
        return contract;
    }

    public void activate(Instant when) {
        if (status != ContractStatus.DRAFT) {
            throw new DomainException("Solo un contrato DRAFT puede activarse");
        }
        if (when == null) {
            throw new DomainException("El instante de activación es obligatorio");
        }
        this.status = ContractStatus.ACTIVE;
        this.activatedAt = when;
    }

    public void complete(Instant when, LocalDate endsOn) {
        if (status != ContractStatus.ACTIVE) {
            throw new DomainException("Solo un contrato ACTIVE puede completarse");
        }
        if (when == null) {
            throw new DomainException("El instante de cierre es obligatorio");
        }
        if (endsOn != null) {
            if (endsOn.isBefore(startsOn)) {
                throw new DomainException("La fecha de fin no puede ser anterior al inicio");
            }
            this.endsOn = endsOn;
        }
        this.status = ContractStatus.COMPLETED;
        this.completedAt = when;
    }

    public void cancel(String actor, Instant when, String reason) {
        if (status == ContractStatus.COMPLETED || status == ContractStatus.CANCELLED) {
            throw new DomainException("No se puede anular un contrato " + status);
        }
        if (when == null) {
            throw new DomainException("El instante de anulación es obligatorio");
        }
        this.status = ContractStatus.CANCELLED;
        this.cancelledAt = when;
        this.cancelledBy = actor == null || actor.isBlank() ? "sistema" : actor.trim();
        this.cancelReason = reason == null || reason.isBlank() ? "Anulación de contrato" : reason.trim();
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

    public ContractType getContractType() {
        return contractType;
    }

    public ContractStatus getStatus() {
        return status;
    }

    public LocalDate getStartsOn() {
        return startsOn;
    }

    public LocalDate getEndsOn() {
        return endsOn;
    }

    public Money getWage() {
        return wage;
    }

    public Instant getRegisteredAt() {
        return registeredAt;
    }

    public Instant getActivatedAt() {
        return activatedAt;
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
