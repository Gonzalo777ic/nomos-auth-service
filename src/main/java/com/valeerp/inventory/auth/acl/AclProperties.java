package com.valeerp.inventory.auth.acl;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Nombres de claims JWT / fixture para menús y permisos.
 * Prefijo: valeerp.acl
 */
@ConfigurationProperties(prefix = "valeerp.acl")
public class AclProperties {

    private String permissionsClaim = "permissions";
    private String groupsClaim = "groups";
    private String menusClaim = "menus";
    private String rolesClaim = "roles";

    public String getPermissionsClaim() {
        return permissionsClaim;
    }

    public void setPermissionsClaim(String permissionsClaim) {
        this.permissionsClaim = blankToDefault(permissionsClaim, "permissions");
    }

    public String getGroupsClaim() {
        return groupsClaim;
    }

    public void setGroupsClaim(String groupsClaim) {
        this.groupsClaim = blankToDefault(groupsClaim, "groups");
    }

    public String getMenusClaim() {
        return menusClaim;
    }

    public void setMenusClaim(String menusClaim) {
        this.menusClaim = blankToDefault(menusClaim, "menus");
    }

    public String getRolesClaim() {
        return rolesClaim;
    }

    public void setRolesClaim(String rolesClaim) {
        this.rolesClaim = blankToDefault(rolesClaim, "roles");
    }

    private static String blankToDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }
}
