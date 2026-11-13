package com.valeerp.inventory.auth.acl.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import java.util.ArrayList;
import java.util.List;

public class CreateUserRequest {

    @NotBlank
    private String username;

    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String password;

    private List<String> roleNames = new ArrayList<>();

    private List<String> groupCodes = new ArrayList<>();

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<String> getRoleNames() {
        return roleNames;
    }

    public void setRoleNames(List<String> roleNames) {
        this.roleNames = roleNames == null ? new ArrayList<>() : roleNames;
    }

    public List<String> getGroupCodes() {
        return groupCodes;
    }

    public void setGroupCodes(List<String> groupCodes) {
        this.groupCodes = groupCodes == null ? new ArrayList<>() : groupCodes;
    }
}
