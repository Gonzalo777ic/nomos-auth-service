package com.valeerp.inventory.auth.acl.dto;

import com.valeerp.inventory.auth.acl.SecurityGroup;

import java.util.List;
import java.util.stream.Collectors;

public class SecurityGroupResponse {

    private final Long id;
    private final String code;
    private final String name;
    private final String description;
    private final List<String> permissions;

    private SecurityGroupResponse(
            Long id,
            String code,
            String name,
            String description,
            List<String> permissions
    ) {
        this.id = id;
        this.code = code;
        this.name = name;
        this.description = description;
        this.permissions = permissions;
    }

    public static SecurityGroupResponse from(SecurityGroup group) {
        return new SecurityGroupResponse(
                group.getId(),
                group.getCode(),
                group.getName(),
                group.getDescription(),
                group.getPermissions().stream()
                        .map(permission -> permission.getCode())
                        .sorted()
                        .collect(Collectors.toList())
        );
    }

    public Long getId() {
        return id;
    }

    public String getCode() {
        return code;
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
