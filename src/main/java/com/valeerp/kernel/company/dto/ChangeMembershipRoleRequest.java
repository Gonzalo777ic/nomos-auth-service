package com.valeerp.kernel.company.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class ChangeMembershipRoleRequest {

    @NotBlank(message = "El rol de pertenencia es obligatorio")
    @Size(max = 32)
    private String role;

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
