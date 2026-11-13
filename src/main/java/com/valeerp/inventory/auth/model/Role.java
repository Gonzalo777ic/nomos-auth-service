package com.valeerp.inventory.auth.model;

import com.valeerp.inventory.auth.acl.Permission;
import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.SoftDeletable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Rol de identidad (compat Spring ROLE_*). Permisos granulares vía ACL.
 * Maestro con soft-delete. Sin ficha comercial ni supplierId.
 */
@Entity
@Table(name = "roles")
public class Role extends SoftDeletable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 80)
    private String name;

    @Column(length = 255)
    private String description;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "role_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    private Set<Permission> permissions = new HashSet<>();

    protected Role() {
    }

    public static Role define(String name, String description) {
        Role role = new Role();
        role.rename(name);
        role.description = description == null ? null : description.trim();
        return role;
    }

    public void rename(String name) {
        if (name == null || name.isBlank()) {
            throw new DomainException("El nombre del rol es obligatorio");
        }
        String normalized = name.trim().toUpperCase();
        this.name = normalized.startsWith("ROLE_") ? normalized : "ROLE_" + normalized;
    }

    public void grant(Permission permission) {
        if (permission == null) {
            throw new DomainException("El permiso a otorgar es obligatorio");
        }
        permissions.add(permission);
    }

    public void revoke(Permission permission) {
        if (permission == null) {
            throw new DomainException("El permiso a revocar es obligatorio");
        }
        permissions.remove(permission);
    }

    public void replacePermissions(Set<Permission> next) {
        permissions.clear();
        if (next != null) {
            permissions.addAll(next);
        }
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

    public Set<Permission> getPermissions() {
        return Collections.unmodifiableSet(permissions);
    }
}
