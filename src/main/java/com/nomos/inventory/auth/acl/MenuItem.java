package com.nomos.inventory.auth.acl;

import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.SoftDeletable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Menú visible según permiso o grupo de seguridad.
 * El frontend puede consumir la API o un claim/fixture con la misma forma.
 */
@Entity
@Table(name = "acl_menu_items")
public class MenuItem extends SoftDeletable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 80)
    private String key;

    @Column(nullable = false, length = 120)
    private String label;

    @Column(name = "parent_key", length = 80)
    private String parentKey;

    @Column(length = 255)
    private String route;

    @Column(name = "required_permission", length = 120)
    private String requiredPermission;

    @Column(name = "required_group", length = 80)
    private String requiredGroup;

    @Column(name = "sort_order", nullable = false)
    private int sortOrder;

    protected MenuItem() {
    }

    public static MenuItem define(
            String key,
            String label,
            String parentKey,
            String route,
            String requiredPermission,
            String requiredGroup,
            int sortOrder
    ) {
        MenuItem item = new MenuItem();
        item.key = requireKey(key);
        item.label = requireLabel(label);
        item.parentKey = blankToNull(parentKey);
        item.route = blankToNull(route);
        item.requiredPermission = blankToNull(requiredPermission);
        item.requiredGroup = blankToNull(requiredGroup);
        item.sortOrder = sortOrder;
        return item;
    }

    public boolean isVisibleTo(SetView access) {
        boolean permissionOk = requiredPermission == null || access.hasPermission(requiredPermission);
        boolean groupOk = requiredGroup == null || access.hasGroup(requiredGroup);
        if (requiredPermission == null && requiredGroup == null) {
            return true;
        }
        if (requiredPermission != null && requiredGroup != null) {
            return permissionOk || groupOk;
        }
        return requiredPermission != null ? permissionOk : groupOk;
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

    private static String requireKey(String key) {
        if (key == null || key.isBlank()) {
            throw new DomainException("La clave del menú es obligatoria");
        }
        return key.trim();
    }

    private static String requireLabel(String label) {
        if (label == null || label.isBlank()) {
            throw new DomainException("La etiqueta del menú es obligatoria");
        }
        return label.trim();
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    /**
     * Vista de acceso del usuario para evaluar visibilidad de menú.
     */
    public interface SetView {
        boolean hasPermission(String permissionCode);

        boolean hasGroup(String groupCode);
    }
}
