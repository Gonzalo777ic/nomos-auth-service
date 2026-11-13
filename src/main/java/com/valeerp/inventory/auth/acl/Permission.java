package com.valeerp.inventory.auth.acl;

import com.valeerp.kernel.DomainException;
import com.valeerp.kernel.SoftDeletable;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Permiso granular app/modelo/acción. Maestro con soft-delete.
 * Identidad no posee ficha comercial ni supplierId.
 */
@Entity
@Table(name = "acl_permissions")
public class Permission extends SoftDeletable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 120)
    private String code;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private ErpApp app;

    @Column(name = "model_name", nullable = false, length = 64)
    private String modelName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private AclAction action;

    @Column(length = 255)
    private String description;

    protected Permission() {
    }

    public static Permission define(ErpApp app, String modelName, AclAction action, String description) {
        Permission permission = new Permission();
        permission.app = app;
        permission.modelName = requireModel(modelName);
        permission.action = requireAction(action);
        permission.code = PermissionCodes.code(app, permission.modelName, permission.action);
        permission.description = description == null ? null : description.trim();
        return permission;
    }

    public static Permission defineFromCode(String code, String description) {
        ParsedCode parsed = ParsedCode.parse(code);
        return define(parsed.app(), parsed.model(), parsed.action(), description);
    }

    public Long getId() {
        return id;
    }

    public String getCode() {
        return code;
    }

    public ErpApp getApp() {
        return app;
    }

    public String getModelName() {
        return modelName;
    }

    public AclAction getAction() {
        return action;
    }

    public String getDescription() {
        return description;
    }

    private static String requireModel(String modelName) {
        if (modelName == null || modelName.isBlank()) {
            throw new DomainException("El modelo del permiso es obligatorio");
        }
        return modelName.trim().toLowerCase().replace(' ', '_');
    }

    private static AclAction requireAction(AclAction action) {
        if (action == null) {
            throw new DomainException("La acción del permiso es obligatoria");
        }
        return action;
    }

    private record ParsedCode(ErpApp app, String model, AclAction action) {

        static ParsedCode parse(String code) {
            if (code == null || code.isBlank()) {
                throw new DomainException("El código de permiso es obligatorio");
            }
            String[] parts = code.trim().toLowerCase().split("\\.");
            if (parts.length != 3) {
                throw new DomainException("El código de permiso debe ser app.model.action");
            }
            return new ParsedCode(ErpApp.require(parts[0]), parts[1], AclAction.require(parts[2]));
        }
    }
}
