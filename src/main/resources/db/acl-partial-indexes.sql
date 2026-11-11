-- Índices parciales para soft-delete de maestros de identidad.
-- Ejecutar tras crear tablas (ddl-auto o migración). No borrar filas físicas.

-- Email reutilizable tras baja lógica
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email_active
    ON users (lower(email))
    WHERE deleted_at IS NULL;

-- Username reutilizable tras baja lógica
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_username_active
    ON users (username)
    WHERE deleted_at IS NULL;

-- auth0Id activo único (nulos permitidos múltiples según motor)
CREATE UNIQUE INDEX IF NOT EXISTS ux_users_auth0_active
    ON users (auth0_id)
    WHERE deleted_at IS NULL AND auth0_id IS NOT NULL;

-- Códigos de permiso / grupo / menú activos
CREATE UNIQUE INDEX IF NOT EXISTS ux_acl_permissions_code_active
    ON acl_permissions (code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_acl_groups_code_active
    ON acl_security_groups (code)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_acl_menus_key_active
    ON acl_menu_items (key)
    WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ux_roles_name_active
    ON roles (name)
    WHERE deleted_at IS NULL;

-- El libro login_sessions NO lleva soft-delete ni índices de ocultamiento.
