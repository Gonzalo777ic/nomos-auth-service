package com.valeerp.hr.dto;

import jakarta.validation.constraints.Size;

/**
 * Anulación documentada de libros RRHH (contrato / ausencia). No es delete.
 */
public class CancelBookRequest {

    @Size(max = 255)
    private String reason;

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
}
