package com.nomos.inventory.auth.acl.dto;

import jakarta.validation.constraints.NotBlank;

public class CreatePermissionRequest {

    @NotBlank
    private String app;

    @NotBlank
    private String model;

    @NotBlank
    private String action;

    private String description;

    public String getApp() {
        return app;
    }

    public void setApp(String app) {
        this.app = app;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
