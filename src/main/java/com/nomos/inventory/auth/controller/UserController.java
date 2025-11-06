package com.nomos.inventory.auth.controller;

import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth/users")
@RequiredArgsConstructor
public class UserController {



    private final UserService userService;


    public static class InternalUserDTO {
        public Long id;
        public String username; // Mapea el campo 'username'
        public String auth0Id;
        public List<String> roles; // ¡NUEVO CAMPO!

        public InternalUserDTO(User user) {
            this.id = user.getId();
            this.username = user.getUsername();
            this.auth0Id = user.getAuth0Id();
            // Mapeamos el Set<Role> a List<String>
            this.roles = user.getRoles().stream()
                    .map(role -> role.getName())
                    .collect(Collectors.toList());
        }
    }


    // DTO simple para enviar al frontend
    public static class UserReferenceDTO {
        public Long id;
        public String name; // Nombre o email para mostrar

        public UserReferenceDTO(User user) {
            this.id = user.getId();
            // Usamos 'username' (que es el email) si no tienes 'fullName' en el modelo User.
            this.name = user.getUsername();
        }
    }

    /**
     * Endpoint: GET /api/auth/users/sellers
     * Obtiene usuarios que tienen el rol de vendedor (actualmente ROLE_ADMIN o ROLE_SELLER).
     */
    @GetMapping("/sellers")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_VENTAS', 'SCOPE_read:users')")
    public ResponseEntity<List<UserReferenceDTO>> getAllSellers() {

        // 🏆 CORRECCIÓN CLAVE: Usar el método que devuelve List<User>
        List<User> sellers = userService.findUsersByRoleName("ROLE_ADMIN");

        List<UserReferenceDTO> dtoList = sellers.stream()
                .map(UserReferenceDTO::new)
                .collect(Collectors.toList());

        return ResponseEntity.ok(dtoList);
    }

    // 🏆 2. NUEVO ENDPOINT: Gestión de Usuarios Internos (CRUD para el Frontend)
    @GetMapping("/internal")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<InternalUserDTO>> getAllInternalUsers() { // 💡 Cambiamos el tipo de retorno
        List<User> internalUsers = userService.findAllInternalUsers();

        List<InternalUserDTO> dtoList = internalUsers.stream()
                .map(InternalUserDTO::new) // 💡 Mapea al InternalUserDTO
                .collect(Collectors.toList());

        return ResponseEntity.ok(dtoList);
    }


}