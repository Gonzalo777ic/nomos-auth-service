package com.valeerp.hr.dto;

import java.time.LocalDate;

public class CompleteContractRequest {

    private LocalDate endsOn;

    public LocalDate getEndsOn() {
        return endsOn;
    }

    public void setEndsOn(LocalDate endsOn) {
        this.endsOn = endsOn;
    }
}
