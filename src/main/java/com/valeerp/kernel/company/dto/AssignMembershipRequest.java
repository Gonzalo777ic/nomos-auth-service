package com.valeerp.kernel.company.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class AssignMembershipRequest {

    @NotNull(message = "El usuario es obligatorio")
    private Long userId;

    @Size(max = 32)
    private String role;

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
