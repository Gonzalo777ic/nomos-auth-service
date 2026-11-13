package com.valeerp.inventory.auth.acl.dto;

import com.valeerp.inventory.auth.model.User;

import java.util.List;
import java.util.stream.Collectors;

public class UserResponse {

    private final Long id;
    private final String username;
    private final String email;
    private final String auth0Id;
    private final List<String> roles;
    private final List<String> groups;
    private final List<String> permissions;

    private UserResponse(
            Long id,
            String username,
            String email,
            String auth0Id,
            List<String> roles,
            List<String> groups,
            List<String> permissions
    ) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.auth0Id = auth0Id;
        this.roles = roles;
        this.groups = groups;
        this.permissions = permissions;
    }

    public static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getAuth0Id(),
                user.roleNames().stream().sorted().collect(Collectors.toList()),
                user.securityGroupCodes().stream().sorted().collect(Collectors.toList()),
                user.effectivePermissionCodes().stream().sorted().collect(Collectors.toList())
        );
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getAuth0Id() {
        return auth0Id;
    }

    public List<String> getRoles() {
        return roles;
    }

    public List<String> getGroups() {
        return groups;
    }

    public List<String> getPermissions() {
        return permissions;
    }
}
