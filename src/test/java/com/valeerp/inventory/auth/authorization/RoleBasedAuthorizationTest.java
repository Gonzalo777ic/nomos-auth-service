package com.valeerp.inventory.auth.authorization;

import com.valeerp.inventory.auth.acl.Permission;
import com.valeerp.inventory.auth.acl.PermissionCodes;
import com.valeerp.inventory.auth.acl.SecurityGroup;
import com.valeerp.inventory.auth.model.Role;
import com.valeerp.inventory.auth.model.RoleEnum;
import com.valeerp.inventory.auth.model.User;
import com.valeerp.kernel.DomainException;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Autorización por rol/grupo con fixtures literales.
 * Sin Auth0, sin Spring context, sin otros servicios.
 */
class RoleBasedAuthorizationTest {

    @Test
    void adminRoleCanWriteAndUnlinkUsers() {
        Permission userWrite = Permission.defineFromCode(PermissionCodes.IDENTITY_USER_WRITE, "write user");
        Permission userUnlink = Permission.defineFromCode(PermissionCodes.IDENTITY_USER_UNLINK, "unlink user");

        Role admin = Role.define(RoleEnum.ROLE_ADMIN.name(), RoleEnum.ROLE_ADMIN.getDescription());
        admin.grant(userWrite);
        admin.grant(userUnlink);

        User actor = User.registerLocal("admin.local", "admin@example.com", "encoded-hash");
        actor.assignRole(admin);

        assertTrue(AccessAuthorizer.allows(actor, PermissionCodes.IDENTITY_USER_WRITE));
        assertDoesNotThrow(() -> AccessAuthorizer.require(actor, PermissionCodes.IDENTITY_USER_UNLINK));
    }

    @Test
    void sellerRoleCannotManageIdentityUsers() {
        Permission salesRead = Permission.defineFromCode(PermissionCodes.SALES_ORDER_READ, "read sale order");

        Role seller = Role.define(RoleEnum.ROLE_SELLER.name(), RoleEnum.ROLE_SELLER.getDescription());
        seller.grant(salesRead);

        User actor = User.registerLocal("seller.local", "seller@example.com", "encoded-hash");
        actor.assignRole(seller);

        assertTrue(AccessAuthorizer.allows(actor, PermissionCodes.SALES_ORDER_READ));
        assertFalse(AccessAuthorizer.allows(actor, PermissionCodes.IDENTITY_USER_WRITE));
        DomainException denied = assertThrows(
                DomainException.class,
                () -> AccessAuthorizer.require(actor, PermissionCodes.IDENTITY_USER_UNLINK)
        );
        assertTrue(denied.getMessage().contains(PermissionCodes.IDENTITY_USER_UNLINK));
    }

    @Test
    void inventoryManagerRoleCanReadStockButNotAccounting() {
        Permission stockRead = Permission.defineFromCode(PermissionCodes.INVENTORY_STOCK_READ, "read stock");
        Permission catalogRead = Permission.defineFromCode(PermissionCodes.CATALOG_PRODUCT_READ, "read product");

        Role manager = Role.define(
                RoleEnum.ROLE_INVENTORY_MANAGER.name(),
                RoleEnum.ROLE_INVENTORY_MANAGER.getDescription()
        );
        manager.grant(stockRead);
        manager.grant(catalogRead);

        User actor = User.registerLocal("stock.mgr", "stock@example.com", "encoded-hash");
        actor.assignRole(manager);

        assertDoesNotThrow(() -> AccessAuthorizer.require(actor, PermissionCodes.INVENTORY_STOCK_READ));
        assertDoesNotThrow(() -> AccessAuthorizer.require(actor, PermissionCodes.CATALOG_PRODUCT_READ));
        assertThrows(
                DomainException.class,
                () -> AccessAuthorizer.require(actor, PermissionCodes.ACCOUNTING_ENTRY_READ)
        );
    }

    @Test
    void securityGroupGrantsPermissionsLikeARole() {
        Permission companyRead = Permission.defineFromCode(PermissionCodes.IDENTITY_COMPANY_READ, "read company");
        Permission companyWrite = Permission.defineFromCode(PermissionCodes.IDENTITY_COMPANY_WRITE, "write company");

        SecurityGroup companyOfficers = SecurityGroup.define(
                "identity_company_officer",
                "Company officers",
                "Puede leer y escribir compañías"
        );
        companyOfficers.grant(companyRead);
        companyOfficers.grant(companyWrite);

        User actor = User.registerLocal("officer", "officer@example.com", "encoded-hash");
        actor.assignSecurityGroup(companyOfficers);

        assertTrue(AccessAuthorizer.allows(actor, PermissionCodes.IDENTITY_COMPANY_WRITE));
        assertFalse(AccessAuthorizer.allows(actor, PermissionCodes.IDENTITY_USER_UNLINK));
    }

    @Test
    void retiredUserIsDeniedEvenWithAdminRole() {
        Permission userRead = Permission.defineFromCode(PermissionCodes.IDENTITY_USER_READ, "read user");
        Role admin = Role.define(RoleEnum.ROLE_ADMIN.name(), RoleEnum.ROLE_ADMIN.getDescription());
        admin.grant(userRead);

        User actor = User.registerLocal("retired.admin", "retired@example.com", "encoded-hash");
        actor.assignRole(admin);
        actor.retire("auditor", Instant.parse("2026-11-10T12:00:00Z"));

        assertFalse(AccessAuthorizer.allows(actor, PermissionCodes.IDENTITY_USER_READ));
        assertThrows(
                DomainException.class,
                () -> AccessAuthorizer.require(actor, PermissionCodes.IDENTITY_USER_READ)
        );
    }

    @Test
    void clientRoleOnlySeesStoreFacingSalesReadWhenGranted() {
        Permission salesRead = Permission.defineFromCode(PermissionCodes.SALES_ORDER_READ, "read own orders");
        Role client = Role.define(RoleEnum.ROLE_CLIENT.name(), RoleEnum.ROLE_CLIENT.getDescription());
        client.grant(salesRead);

        User actor = User.registerLocal("client.web", "client@example.com", "encoded-hash");
        actor.assignRole(client);

        assertDoesNotThrow(() -> AccessAuthorizer.require(actor, PermissionCodes.SALES_ORDER_READ));
        assertThrows(
                DomainException.class,
                () -> AccessAuthorizer.require(actor, PermissionCodes.PURCHASE_ORDER_READ)
        );
    }
}
