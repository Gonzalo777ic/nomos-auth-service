package com.valeerp.inventory.auth.acl.dto;

import com.valeerp.inventory.auth.acl.Permission;

public class PermissionResponse {

    private final Long id;
    private final String code;
    private final String app;
    private final String model;
    private final String action;
    private final String description;

    private PermissionResponse(
            Long id,
            String code,
            String app,
            String model,
            String action,
            String description
    ) {
        this.id = id;
        this.code = code;
        this.app = app;
        this.model = model;
        this.action = action;
        this.description = description;
    }

    public static PermissionResponse from(Permission permission) {
        return new PermissionResponse(
                permission.getId(),
                permission.getCode(),
                permission.getApp().code(),
                permission.getModelName(),
                permission.getAction().code(),
                permission.getDescription()
        );
    }

    public Long getId() {
        return id;
    }

    public String getCode() {
        return code;
    }

    public String getApp() {
        return app;
    }

    public String getModel() {
        return model;
    }

    public String getAction() {
        return action;
    }

    public String getDescription() {
        return description;
    }
}
