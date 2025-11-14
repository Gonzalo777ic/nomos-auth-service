package com.nomos.inventory.auth.model;

import lombok.Getter;

@Getter
public enum RoleEnum {
    // Roles del personal interno (pueden ser usuarios locales o Auth0)
    ROLE_ADMIN("Administrador", "Acceso total al sistema de gestión."),
    ROLE_INVENTORY_MANAGER("Gestor de Inventario", "Gestión de productos y stock."),
    ROLE_SELLER("Vendedor", "Creación de órdenes de venta y cotizaciones."),
    ROLE_DELIVERY("Personal de Reparto", "Gestión de guías de envío y entregas."),

    // Rol externo (exclusivamente Auth0)
    ROLE_CLIENT("Cliente", "Usuario de la tienda web con historial de compras.");

    private final String friendlyName;
    private final String description;

    RoleEnum(String friendlyName, String description) {
        this.friendlyName = friendlyName;
        this.description = description;
    }
}