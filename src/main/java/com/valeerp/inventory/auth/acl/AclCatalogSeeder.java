package com.valeerp.inventory.auth.acl;

import com.valeerp.inventory.auth.model.Role;
import com.valeerp.inventory.auth.model.RoleEnum;
import com.valeerp.inventory.auth.repository.RoleRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Siembra permisos, grupos, menús y asocia permisos al ROLE_ADMIN.
 * No toca multi-compañía.
 */
@Component
@Order(1)
public class AclCatalogSeeder implements CommandLineRunner {

    public static final String GROUP_SYSTEM = "group_system";
    public static final String GROUP_SALES = "group_sales";
    public static final String GROUP_INVENTORY = "group_inventory";
    public static final String GROUP_HR = "group_hr";

    private final PermissionRepository permissionRepository;
    private final SecurityGroupRepository securityGroupRepository;
    private final MenuItemRepository menuItemRepository;
    private final RoleRepository roleRepository;

    public AclCatalogSeeder(
            PermissionRepository permissionRepository,
            SecurityGroupRepository securityGroupRepository,
            MenuItemRepository menuItemRepository,
            RoleRepository roleRepository
    ) {
        this.permissionRepository = permissionRepository;
        this.securityGroupRepository = securityGroupRepository;
        this.menuItemRepository = menuItemRepository;
        this.roleRepository = roleRepository;
    }

    @Override
    @Transactional
    public void run(String... args) {
        seedPermissions();
        seedRolesFromEnum();
        seedGroups();
        seedMenus();
        grantAdminAllPermissions();
    }

    private void seedPermissions() {
        for (String code : PermissionCodes.seedCodes()) {
            if (!permissionRepository.existsByCode(code)) {
                permissionRepository.save(Permission.defineFromCode(code, code));
            }
        }
    }

    private void seedRolesFromEnum() {
        Arrays.stream(RoleEnum.values()).forEach(roleEnum -> {
            if (roleRepository.findByName(roleEnum.name()).isEmpty()) {
                roleRepository.save(Role.define(roleEnum.name(), roleEnum.getDescription()));
            }
        });
    }

    private void seedGroups() {
        ensureGroup(GROUP_SYSTEM, "Administración del sistema", Set.of(PermissionCodes.seedCodes()));
        ensureGroup(GROUP_SALES, "Ventas", Set.of(
                PermissionCodes.SALES_ORDER_READ,
                PermissionCodes.IDENTITY_USER_READ,
                PermissionCodes.IDENTITY_MENU_READ
        ));
        ensureGroup(GROUP_INVENTORY, "Inventario", Set.of(
                PermissionCodes.INVENTORY_STOCK_READ,
                PermissionCodes.CATALOG_PRODUCT_READ,
                PermissionCodes.PURCHASE_ORDER_READ,
                PermissionCodes.IDENTITY_MENU_READ
        ));
        ensureGroup(GROUP_HR, "RRHH", Set.of(
                PermissionCodes.HR_EMPLOYEE_READ,
                PermissionCodes.HR_EMPLOYEE_CREATE,
                PermissionCodes.HR_EMPLOYEE_WRITE,
                PermissionCodes.HR_EMPLOYEE_UNLINK,
                PermissionCodes.HR_DEPARTMENT_READ,
                PermissionCodes.HR_DEPARTMENT_WRITE,
                PermissionCodes.HR_POSITION_READ,
                PermissionCodes.HR_POSITION_WRITE,
                PermissionCodes.HR_CONTRACT_READ,
                PermissionCodes.HR_CONTRACT_WRITE,
                PermissionCodes.HR_ABSENCE_READ,
                PermissionCodes.HR_ABSENCE_WRITE,
                PermissionCodes.IDENTITY_MENU_READ,
                PermissionCodes.IDENTITY_COMPANY_READ
        ));
    }

    private void ensureGroup(String code, String name, Set<String> permissionCodes) {
        SecurityGroup group = securityGroupRepository.findByCode(code)
                .orElseGet(() -> securityGroupRepository.save(SecurityGroup.define(code, name, name)));
        Set<Permission> permissions = new HashSet<>();
        for (String permissionCode : permissionCodes) {
            permissionRepository.findByCode(permissionCode).ifPresent(permissions::add);
        }
        group.replacePermissions(permissions);
        securityGroupRepository.save(group);
    }

    private void seedMenus() {
        ensureMenu("menu.identity", "Identidad", null, "/identity", null, GROUP_SYSTEM, 10);
        ensureMenu(
                "menu.identity.users",
                "Usuarios",
                "menu.identity",
                "/identity/users",
                PermissionCodes.IDENTITY_USER_READ,
                null,
                11
        );
        ensureMenu(
                "menu.identity.roles",
                "Roles y permisos",
                "menu.identity",
                "/identity/roles",
                PermissionCodes.IDENTITY_ROLE_READ,
                null,
                12
        );
        ensureMenu(
                "menu.identity.groups",
                "Grupos de seguridad",
                "menu.identity",
                "/identity/groups",
                PermissionCodes.IDENTITY_GROUP_READ,
                null,
                13
        );
        ensureMenu(
                "menu.identity.sessions",
                "Sesiones",
                "menu.identity",
                "/identity/sessions",
                PermissionCodes.IDENTITY_SESSION_READ,
                null,
                14
        );
        ensureMenu(
                "menu.identity.companies",
                "Compañías",
                "menu.identity",
                "/identity/companies",
                PermissionCodes.IDENTITY_COMPANY_READ,
                null,
                15
        );
        ensureMenu("menu.catalog", "Catálogo", null, "/catalog", PermissionCodes.CATALOG_PRODUCT_READ, null, 20);
        ensureMenu("menu.inventory", "Inventario", null, "/inventory", PermissionCodes.INVENTORY_STOCK_READ, null, 30);
        ensureMenu("menu.purchase", "Compras", null, "/purchase", PermissionCodes.PURCHASE_ORDER_READ, null, 40);
        ensureMenu("menu.sales", "Ventas", null, "/sales", PermissionCodes.SALES_ORDER_READ, null, 50);
        ensureMenu("menu.accounting", "Contabilidad", null, "/accounting", PermissionCodes.ACCOUNTING_ENTRY_READ, null, 60);
        ensureMenu("menu.hr", "RRHH", null, "/hr", PermissionCodes.HR_EMPLOYEE_READ, GROUP_HR, 70);
        ensureMenu(
                "menu.hr.employees",
                "Empleados",
                "menu.hr",
                "/hr/employees",
                PermissionCodes.HR_EMPLOYEE_READ,
                null,
                71
        );
        ensureMenu(
                "menu.hr.departments",
                "Departamentos",
                "menu.hr",
                "/hr/departments",
                PermissionCodes.HR_DEPARTMENT_READ,
                null,
                72
        );
        ensureMenu(
                "menu.hr.positions",
                "Puestos",
                "menu.hr",
                "/hr/positions",
                PermissionCodes.HR_POSITION_READ,
                null,
                73
        );
        ensureMenu(
                "menu.hr.contracts",
                "Contratos",
                "menu.hr",
                "/hr/contracts",
                PermissionCodes.HR_CONTRACT_READ,
                null,
                74
        );
        ensureMenu(
                "menu.hr.absences",
                "Ausencias",
                "menu.hr",
                "/hr/absences",
                PermissionCodes.HR_ABSENCE_READ,
                null,
                75
        );
    }

    private void ensureMenu(
            String key,
            String label,
            String parentKey,
            String route,
            String requiredPermission,
            String requiredGroup,
            int sortOrder
    ) {
        if (!menuItemRepository.existsByKey(key)) {
            menuItemRepository.save(MenuItem.define(
                    key, label, parentKey, route, requiredPermission, requiredGroup, sortOrder
            ));
        }
    }

    private void grantAdminAllPermissions() {
        roleRepository.findByName(RoleEnum.ROLE_ADMIN.name()).ifPresent(admin -> {
            Set<Permission> all = new HashSet<>(permissionRepository.findAll());
            admin.replacePermissions(all);
            roleRepository.save(admin);
        });
    }
}
