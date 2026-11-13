package com.valeerp.inventory.auth.acl.dto;

import java.util.ArrayList;
import java.util.List;

/**
 * Snapshot de acceso para claims JWT / fixtures del Admin ERP.
 *
 * <pre>
 * {
 *   "username": "admin@example.com",
 *   "roles": ["ROLE_ADMIN"],
 *   "groups": ["group_system"],
 *   "permissions": ["identity.user.read", "identity.menu.read"],
 *   "menus": [ { "key": "menu.identity.users", ... } ]
 * }
 * </pre>
 */
public class AccessSnapshotResponse {

    private final String username;
    private final List<String> roles;
    private final List<String> groups;
    private final List<String> permissions;
    private final List<MenuItemResponse> menus;

    public AccessSnapshotResponse(
            String username,
            List<String> roles,
            List<String> groups,
            List<String> permissions,
            List<MenuItemResponse> menus
    ) {
        this.username = username;
        this.roles = roles == null ? List.of() : List.copyOf(roles);
        this.groups = groups == null ? List.of() : List.copyOf(groups);
        this.permissions = permissions == null ? List.of() : List.copyOf(permissions);
        this.menus = menus == null ? List.of() : List.copyOf(menus);
    }

    public String getUsername() {
        return username;
    }

    public List<String> getRoles() {
        return new ArrayList<>(roles);
    }

    public List<String> getGroups() {
        return new ArrayList<>(groups);
    }

    public List<String> getPermissions() {
        return new ArrayList<>(permissions);
    }

    public List<MenuItemResponse> getMenus() {
        return new ArrayList<>(menus);
    }
}
