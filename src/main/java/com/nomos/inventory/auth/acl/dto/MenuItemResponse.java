package com.nomos.inventory.auth.acl.dto;

import com.nomos.inventory.auth.acl.MenuItem;

/**
 * Forma estable de menú para API, claim JWT y fixtures locales del frontend.
 *
 * <pre>
 * {
 *   "key": "menu.identity.users",
 *   "label": "Usuarios",
 *   "parentKey": "menu.identity",
 *   "route": "/identity/users",
 *   "requiredPermission": "identity.user.read",
 *   "requiredGroup": null,
 *   "sortOrder": 10
 * }
 * </pre>
 */
public class MenuItemResponse {

    private final Long id;
    private final String key;
    private final String label;
    private final String parentKey;
    private final String route;
    private final String requiredPermission;
    private final String requiredGroup;
    private final int sortOrder;

    private MenuItemResponse(
            Long id,
            String key,
            String label,
            String parentKey,
            String route,
            String requiredPermission,
            String requiredGroup,
            int sortOrder
    ) {
        this.id = id;
        this.key = key;
        this.label = label;
        this.parentKey = parentKey;
        this.route = route;
        this.requiredPermission = requiredPermission;
        this.requiredGroup = requiredGroup;
        this.sortOrder = sortOrder;
    }

    public static MenuItemResponse from(MenuItem item) {
        return new MenuItemResponse(
                item.getId(),
                item.getKey(),
                item.getLabel(),
                item.getParentKey(),
                item.getRoute(),
                item.getRequiredPermission(),
                item.getRequiredGroup(),
                item.getSortOrder()
        );
    }

    public Long getId() {
        return id;
    }

    public String getKey() {
        return key;
    }

    public String getLabel() {
        return label;
    }

    public String getParentKey() {
        return parentKey;
    }

    public String getRoute() {
        return route;
    }

    public String getRequiredPermission() {
        return requiredPermission;
    }

    public String getRequiredGroup() {
        return requiredGroup;
    }

    public int getSortOrder() {
        return sortOrder;
    }
}
