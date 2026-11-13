package com.valeerp.inventory.auth.acl.dto;

import jakarta.validation.constraints.NotBlank;

import java.util.ArrayList;
import java.util.List;

public class CreateSecurityGroupRequest {

    @NotBlank
    private String code;

    @NotBlank
    private String name;

    private String description;

    private List<String> permissionCodes = new ArrayList<>();

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getPermissionCodes() {
        return permissionCodes;
    }

    public void setPermissionCodes(List<String> permissionCodes) {
        this.permissionCodes = permissionCodes == null ? new ArrayList<>() : permissionCodes;
    }
}
