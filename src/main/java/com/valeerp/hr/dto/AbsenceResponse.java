package com.valeerp.hr.dto;

import com.valeerp.hr.Absence;

import java.time.Instant;
import java.time.LocalDate;

public class AbsenceResponse {

    private final Long id;
    private final Long employeeId;
    private final Long companyId;
    private final String absenceType;
    private final String status;
    private final LocalDate startsOn;
    private final LocalDate endsOn;
    private final String reason;
    private final Instant registeredAt;
    private final Instant approvedAt;
    private final Instant completedAt;
    private final Instant cancelledAt;
    private final String cancelledBy;
    private final String cancelReason;

    private AbsenceResponse(
            Long id,
            Long employeeId,
            Long companyId,
            String absenceType,
            String status,
            LocalDate startsOn,
            LocalDate endsOn,
            String reason,
            Instant registeredAt,
            Instant approvedAt,
            Instant completedAt,
            Instant cancelledAt,
            String cancelledBy,
            String cancelReason
    ) {
        this.id = id;
        this.employeeId = employeeId;
        this.companyId = companyId;
        this.absenceType = absenceType;
        this.status = status;
        this.startsOn = startsOn;
        this.endsOn = endsOn;
        this.reason = reason;
        this.registeredAt = registeredAt;
        this.approvedAt = approvedAt;
        this.completedAt = completedAt;
        this.cancelledAt = cancelledAt;
        this.cancelledBy = cancelledBy;
        this.cancelReason = cancelReason;
    }

    public static AbsenceResponse from(Absence absence) {
        return new AbsenceResponse(
                absence.getId(),
                absence.getEmployeeId(),
                absence.getCompanyId(),
                absence.getAbsenceType().name(),
                absence.getStatus().name(),
                absence.getStartsOn(),
                absence.getEndsOn(),
                absence.getReason(),
                absence.getRegisteredAt(),
                absence.getApprovedAt(),
                absence.getCompletedAt(),
                absence.getCancelledAt(),
                absence.getCancelledBy(),
                absence.getCancelReason()
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

    public String getAbsenceType() {
        return absenceType;
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
