package com.valeerp.hr.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.LocalDate;

public class CreateAbsenceRequest {

    @NotNull(message = "El empleado es obligatorio")
    private Long employeeId;

    private String absenceType;

    @NotNull(message = "La fecha de inicio es obligatoria")
    private LocalDate startsOn;

    @NotNull(message = "La fecha de fin es obligatoria")
    private LocalDate endsOn;

    @Size(max = 500)
    private String reason;

    public Long getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(Long employeeId) {
        this.employeeId = employeeId;
    }

    public String getAbsenceType() {
        return absenceType;
    }

    public void setAbsenceType(String absenceType) {
        this.absenceType = absenceType;
    }

    public LocalDate getStartsOn() {
        return startsOn;
    }

    public void setStartsOn(LocalDate startsOn) {
        this.startsOn = startsOn;
    }

    public LocalDate getEndsOn() {
        return endsOn;
    }

    public void setEndsOn(LocalDate endsOn) {
        this.endsOn = endsOn;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
}
