package com.valeerp.inventory.auth.acl;

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
 * Grupo de seguridad estilo Odoo (res.groups). Maestro con soft-delete.
 */
@Entity
@Table(name = "acl_security_groups")
public class SecurityGroup extends SoftDeletable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 80)
    private String code;

    @Column(nullable = false, length = 120)
    private String name;

    @Column(length = 255)
    private String description;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "acl_group_permissions",
            joinColumns = @JoinColumn(name = "group_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    private Set<Permission> permissions = new HashSet<>();

    protected SecurityGroup() {
    }

    public static SecurityGroup define(String code, String name, String description) {
        SecurityGroup group = new SecurityGroup();
        group.rename(code, name);
        group.description = description == null ? null : description.trim();
        return group;
    }

    public void rename(String code, String name) {
        if (code == null || code.isBlank()) {
            throw new DomainException("El código del grupo es obligatorio");
        }
        if (name == null || name.isBlank()) {
            throw new DomainException("El nombre del grupo es obligatorio");
        }
        this.code = code.trim().toLowerCase();
        this.name = name.trim();
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

    public String getCode() {
        return code;
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
