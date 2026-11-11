package com.nomos.inventory.auth.model;

import com.nomos.inventory.auth.acl.Permission;
import com.nomos.inventory.auth.acl.SecurityGroup;
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
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Credencial de identidad. No posee ficha comercial, dirección ni supplierId.
 * Soft-delete con reactivación; unicidad parcial de email/username en BD
 * ({@code WHERE deleted_at IS NULL}).
 */
@Entity
@Table(name = "users")
public class User extends SoftDeletable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "auth0_id", length = 120)
    private String auth0Id;

    @Column(nullable = false, length = 180)
    private String username;

    @Column(nullable = false, length = 180)
    private String email;

    @Column(length = 255)
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<Role> roles = new HashSet<>();

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_security_groups",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "group_id")
    )
    private Set<SecurityGroup> securityGroups = new HashSet<>();

    protected User() {
    }

    public static User registerLocal(String username, String email, String encodedPassword) {
        User user = new User();
        user.changeIdentity(username, email);
        user.changePassword(encodedPassword);
        return user;
    }

    public static User registerAuth0(String auth0Id, String email) {
        User user = new User();
        user.bindAuth0Id(auth0Id);
        user.changeIdentity(email, email);
        return user;
    }

    public void changeIdentity(String username, String email) {
        if (username == null || username.isBlank()) {
            throw new DomainException("El username es obligatorio");
        }
        if (email == null || email.isBlank()) {
            throw new DomainException("El email es obligatorio");
        }
        this.username = username.trim();
        this.email = email.trim().toLowerCase();
    }

    public void changePassword(String encodedPassword) {
        if (encodedPassword == null || encodedPassword.isBlank()) {
            throw new DomainException("La contraseña es obligatoria");
        }
        this.password = encodedPassword;
    }

    public void clearPassword() {
        this.password = null;
    }

    public void bindAuth0Id(String auth0Id) {
        if (auth0Id == null || auth0Id.isBlank()) {
            throw new DomainException("El auth0Id es obligatorio");
        }
        this.auth0Id = auth0Id.trim();
    }

    public void replaceRoles(Set<Role> next) {
        roles.clear();
        if (next != null) {
            roles.addAll(next);
        }
    }

    public void assignRole(Role role) {
        if (role == null) {
            throw new DomainException("El rol es obligatorio");
        }
        roles.add(role);
    }

    public void assignSecurityGroup(SecurityGroup group) {
        if (group == null) {
            throw new DomainException("El grupo de seguridad es obligatorio");
        }
        securityGroups.add(group);
    }

    public void revokeSecurityGroup(SecurityGroup group) {
        if (group == null) {
            throw new DomainException("El grupo de seguridad es obligatorio");
        }
        securityGroups.remove(group);
    }

    public void reactivate() {
        if (!isRetired()) {
            throw new DomainException("El usuario no está dado de baja");
        }
        restore();
    }

    public Set<String> effectivePermissionCodes() {
        Set<String> codes = new HashSet<>();
        for (Role role : roles) {
            for (Permission permission : role.getPermissions()) {
                codes.add(permission.getCode());
            }
        }
        for (SecurityGroup group : securityGroups) {
            for (Permission permission : group.getPermissions()) {
                codes.add(permission.getCode());
            }
        }
        return codes;
    }

    public Set<String> securityGroupCodes() {
        return securityGroups.stream().map(SecurityGroup::getCode).collect(Collectors.toSet());
    }

    public Set<String> roleNames() {
        return roles.stream().map(Role::getName).collect(Collectors.toSet());
    }

    public Long getId() {
        return id;
    }

    public String getAuth0Id() {
        return auth0Id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public Set<Role> getRoles() {
        return Collections.unmodifiableSet(roles);
    }

    public Set<SecurityGroup> getSecurityGroups() {
        return Collections.unmodifiableSet(securityGroups);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof User user)) {
            return false;
        }
        return id != null && Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}
