package com.nomos.inventory.auth.acl.dto;

import com.nomos.inventory.auth.model.Role;

import java.util.List;
import java.util.stream.Collectors;

public class RoleResponse {

    private final Long id;
    private final String name;
    private final String description;
    private final List<String> permissions;

    private RoleResponse(Long id, String name, String description, List<String> permissions) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.permissions = permissions;
    }

    public static RoleResponse from(Role role) {
        return new RoleResponse(
                role.getId(),
                role.getName(),
                role.getDescription(),
                role.getPermissions().stream()
                        .map(permission -> permission.getCode())
                        .sorted()
                        .collect(Collectors.toList())
        );
    }

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getPermissions() {
        return permissions;
    }
}
