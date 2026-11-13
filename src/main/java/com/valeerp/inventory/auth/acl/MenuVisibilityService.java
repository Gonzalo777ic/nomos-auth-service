package com.valeerp.inventory.auth.acl;

import com.valeerp.inventory.auth.acl.dto.AccessSnapshotResponse;
import com.valeerp.inventory.auth.acl.dto.MenuItemResponse;
import com.valeerp.inventory.auth.model.User;
import com.valeerp.inventory.auth.repository.UserRepository;
import com.valeerp.kernel.DomainException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * Resuelve menús visibles según permisos/grupos del usuario de identidad.
 */
@Service
public class MenuVisibilityService {

    private final MenuItemRepository menuItemRepository;
    private final UserRepository userRepository;

    public MenuVisibilityService(MenuItemRepository menuItemRepository, UserRepository userRepository) {
        this.menuItemRepository = menuItemRepository;
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public List<MenuItemResponse> listAllMenus() {
        return menuItemRepository.findAllByOrderBySortOrderAscKeyAsc().stream()
                .map(MenuItemResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<MenuItemResponse> visibleMenusForUsername(String username) {
        User user = userRepository.findByUsername(username)
                .or(() -> userRepository.findByEmail(username))
                .orElseThrow(() -> new DomainException("Usuario no encontrado"));
        return visibleMenusFor(user);
    }

    @Transactional(readOnly = true)
    public AccessSnapshotResponse accessSnapshot(String username) {
        User user = userRepository.findByUsername(username)
                .or(() -> userRepository.findByEmail(username))
                .orElseThrow(() -> new DomainException("Usuario no encontrado"));
        return accessSnapshot(user);
    }

    @Transactional(readOnly = true)
    public AccessSnapshotResponse accessSnapshot(User user) {
        List<String> roles = user.roleNames().stream().sorted().toList();
        List<String> groups = user.securityGroupCodes().stream().sorted().toList();
        List<String> permissions = user.effectivePermissionCodes().stream().sorted().toList();
        return new AccessSnapshotResponse(
                user.getUsername(),
                roles,
                groups,
                permissions,
                visibleMenusFor(user)
        );
    }

    private List<MenuItemResponse> visibleMenusFor(User user) {
        Set<String> permissions = user.effectivePermissionCodes();
        Set<String> groups = user.securityGroupCodes();
        MenuItem.SetView access = new MenuItem.SetView() {
            @Override
            public boolean hasPermission(String permissionCode) {
                return permissions.contains(permissionCode);
            }

            @Override
            public boolean hasGroup(String groupCode) {
                return groups.contains(groupCode);
            }
        };
        return menuItemRepository.findAllByOrderBySortOrderAscKeyAsc().stream()
                .filter(item -> item.isVisibleTo(access))
                .sorted(Comparator.comparingInt(MenuItem::getSortOrder).thenComparing(MenuItem::getKey))
                .map(MenuItemResponse::from)
                .toList();
    }
}
