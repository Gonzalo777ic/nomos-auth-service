package com.valeerp.hr.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import java.time.LocalDate;

public class CreateContractRequest {

    @NotNull(message = "El empleado es obligatorio")
    private Long employeeId;

    private String contractType;

    @NotNull(message = "La fecha de inicio es obligatoria")
    private LocalDate startsOn;

    private LocalDate endsOn;

    @NotNull(message = "La remuneración es obligatoria")
    @Valid
    private MoneyDto wage;

    public Long getEmployeeId() {
        return employeeId;
    }

    public void setEmployeeId(Long employeeId) {
        this.employeeId = employeeId;
    }

    public String getContractType() {
        return contractType;
    }

    public void setContractType(String contractType) {
        this.contractType = contractType;
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

    public MoneyDto getWage() {
        return wage;
    }

    public void setWage(MoneyDto wage) {
        this.wage = wage;
    }
}
