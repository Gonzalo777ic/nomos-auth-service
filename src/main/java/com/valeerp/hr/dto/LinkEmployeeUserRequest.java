package com.valeerp.hr.dto;

import jakarta.validation.constraints.NotNull;

/**
 * Vincula ficha RRHH a User de identidad por id únicamente.
 */
public class LinkEmployeeUserRequest {

    @NotNull(message = "El userId es obligatorio")
    private Long userId;

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }
}
