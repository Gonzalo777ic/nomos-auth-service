package com.nomos.inventory.auth.acl;

import com.valeerp.kernel.DomainException;

/**
 * Catálogo de códigos de permiso {@code app.model.action}.
 * Un solo lugar de política; controladores y seeds lo consultan.
 */
public final class PermissionCodes {

    public static final String IDENTITY_USER_READ = code(ErpApp.IDENTITY, "user", AclAction.READ);
    public static final String IDENTITY_USER_CREATE = code(ErpApp.IDENTITY, "user", AclAction.CREATE);
    public static final String IDENTITY_USER_WRITE = code(ErpApp.IDENTITY, "user", AclAction.WRITE);
    public static final String IDENTITY_USER_UNLINK = code(ErpApp.IDENTITY, "user", AclAction.UNLINK);

    public static final String IDENTITY_ROLE_READ = code(ErpApp.IDENTITY, "role", AclAction.READ);
    public static final String IDENTITY_ROLE_WRITE = code(ErpApp.IDENTITY, "role", AclAction.WRITE);

    public static final String IDENTITY_GROUP_READ = code(ErpApp.IDENTITY, "security_group", AclAction.READ);
    public static final String IDENTITY_GROUP_WRITE = code(ErpApp.IDENTITY, "security_group", AclAction.WRITE);

    public static final String IDENTITY_MENU_READ = code(ErpApp.IDENTITY, "menu", AclAction.READ);
    public static final String IDENTITY_SESSION_READ = code(ErpApp.IDENTITY, "session", AclAction.READ);
    public static final String IDENTITY_SESSION_WRITE = code(ErpApp.IDENTITY, "session", AclAction.WRITE);

    public static final String IDENTITY_COMPANY_READ = code(ErpApp.IDENTITY, "company", AclAction.READ);
    public static final String IDENTITY_COMPANY_WRITE = code(ErpApp.IDENTITY, "company", AclAction.WRITE);

    public static final String HR_EMPLOYEE_READ = code(ErpApp.HR, "employee", AclAction.READ);
    public static final String HR_EMPLOYEE_CREATE = code(ErpApp.HR, "employee", AclAction.CREATE);
    public static final String HR_EMPLOYEE_WRITE = code(ErpApp.HR, "employee", AclAction.WRITE);
    public static final String HR_EMPLOYEE_UNLINK = code(ErpApp.HR, "employee", AclAction.UNLINK);

    public static final String HR_DEPARTMENT_READ = code(ErpApp.HR, "department", AclAction.READ);
    public static final String HR_DEPARTMENT_WRITE = code(ErpApp.HR, "department", AclAction.WRITE);
    public static final String HR_POSITION_READ = code(ErpApp.HR, "position", AclAction.READ);
    public static final String HR_POSITION_WRITE = code(ErpApp.HR, "position", AclAction.WRITE);

    public static final String HR_CONTRACT_READ = code(ErpApp.HR, "contract", AclAction.READ);
    public static final String HR_CONTRACT_WRITE = code(ErpApp.HR, "contract", AclAction.WRITE);
    public static final String HR_ABSENCE_READ = code(ErpApp.HR, "absence", AclAction.READ);
    public static final String HR_ABSENCE_WRITE = code(ErpApp.HR, "absence", AclAction.WRITE);

    public static final String CATALOG_PRODUCT_READ = code(ErpApp.CATALOG, "product", AclAction.READ);
    public static final String INVENTORY_STOCK_READ = code(ErpApp.INVENTORY, "stock", AclAction.READ);
    public static final String PURCHASE_ORDER_READ = code(ErpApp.PURCHASE, "order", AclAction.READ);
    public static final String SALES_ORDER_READ = code(ErpApp.SALES, "order", AclAction.READ);
    public static final String ACCOUNTING_ENTRY_READ = code(ErpApp.ACCOUNTING, "entry", AclAction.READ);

    private PermissionCodes() {
    }

    public static String code(ErpApp app, String model, AclAction action) {
        if (app == null) {
            throw new DomainException("La app del permiso es obligatoria");
        }
        if (model == null || model.isBlank()) {
            throw new DomainException("El modelo del permiso es obligatorio");
        }
        if (action == null) {
            throw new DomainException("La acción del permiso es obligatoria");
        }
        String normalizedModel = model.trim().toLowerCase().replace(' ', '_');
        return app.code() + "." + normalizedModel + "." + action.code();
    }

    public static String[] seedCodes() {
        return new String[]{
                IDENTITY_USER_READ, IDENTITY_USER_CREATE, IDENTITY_USER_WRITE, IDENTITY_USER_UNLINK,
                IDENTITY_ROLE_READ, IDENTITY_ROLE_WRITE,
                IDENTITY_GROUP_READ, IDENTITY_GROUP_WRITE,
                IDENTITY_MENU_READ,
                IDENTITY_SESSION_READ, IDENTITY_SESSION_WRITE,
                IDENTITY_COMPANY_READ, IDENTITY_COMPANY_WRITE,
                HR_EMPLOYEE_READ, HR_EMPLOYEE_CREATE, HR_EMPLOYEE_WRITE, HR_EMPLOYEE_UNLINK,
                HR_DEPARTMENT_READ, HR_DEPARTMENT_WRITE,
                HR_POSITION_READ, HR_POSITION_WRITE,
                HR_CONTRACT_READ, HR_CONTRACT_WRITE,
                HR_ABSENCE_READ, HR_ABSENCE_WRITE,
                CATALOG_PRODUCT_READ, INVENTORY_STOCK_READ, PURCHASE_ORDER_READ,
                SALES_ORDER_READ, ACCOUNTING_ENTRY_READ
        };
    }
}
