package com.valeerp.hr.dto;

import com.valeerp.hr.EmploymentContract;

import java.time.Instant;
import java.time.LocalDate;

public class ContractResponse {

    private final Long id;
    private final Long employeeId;
    private final Long companyId;
    private final String contractType;
    private final String status;
    private final LocalDate startsOn;
    private final LocalDate endsOn;
    private final MoneyDto wage;
    private final Instant registeredAt;
    private final Instant activatedAt;
    private final Instant completedAt;
    private final Instant cancelledAt;
    private final String cancelledBy;
    private final String cancelReason;

    private ContractResponse(
            Long id,
            Long employeeId,
            Long companyId,
            String contractType,
            String status,
            LocalDate startsOn,
            LocalDate endsOn,
            MoneyDto wage,
            Instant registeredAt,
            Instant activatedAt,
            Instant completedAt,
            Instant cancelledAt,
            String cancelledBy,
            String cancelReason
    ) {
        this.id = id;
        this.employeeId = employeeId;
        this.companyId = companyId;
        this.contractType = contractType;
        this.status = status;
        this.startsOn = startsOn;
        this.endsOn = endsOn;
        this.wage = wage;
        this.registeredAt = registeredAt;
        this.activatedAt = activatedAt;
        this.completedAt = completedAt;
        this.cancelledAt = cancelledAt;
        this.cancelledBy = cancelledBy;
        this.cancelReason = cancelReason;
    }

    public static ContractResponse from(EmploymentContract contract) {
        return new ContractResponse(
                contract.getId(),
                contract.getEmployeeId(),
                contract.getCompanyId(),
                contract.getContractType().name(),
                contract.getStatus().name(),
                contract.getStartsOn(),
                contract.getEndsOn(),
                MoneyDto.from(contract.getWage()),
                contract.getRegisteredAt(),
                contract.getActivatedAt(),
                contract.getCompletedAt(),
                contract.getCancelledAt(),
                contract.getCancelledBy(),
                contract.getCancelReason()
        );
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

    public String getContractType() {
        return contractType;
    }

    public String getStatus() {
        return status;
    }

    public LocalDate getStartsOn() {
        return startsOn;
    }

    public LocalDate getEndsOn() {
        return endsOn;
    }

    public MoneyDto getWage() {
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
