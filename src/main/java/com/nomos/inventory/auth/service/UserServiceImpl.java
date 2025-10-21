package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.model.Role;
import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.repository.RoleRepository;
import com.nomos.inventory.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import jakarta.transaction.Transactional;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import com.nomos.inventory.auth.repository.ClientRepository;
import com.nomos.inventory.auth.model.Client;

@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final ClientRepository clientRepository;

    // Métodos existentes de la interfaz UserService
    @Override
    public User saveUser(User user) {
        // Asegurar que la contraseña solo se encripte y guarde si no es un usuario Auth0
        if (user.getPassword() != null) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        return userRepository.save(user);
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public Role saveRole(Role role) {
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
        Role role = roleRepository.findByName(roleName).orElseThrow(() -> new RuntimeException("Role not found"));

        Set<Role> roles = user.getRoles();
        if (roles == null) {
            roles = new HashSet<>();
        }
        roles.add(role);
        user.setRoles(roles);
        userRepository.save(user);
    }

    @Override
    public Optional<Role> findByRoleName(String roleName) {
        return roleRepository.findByName(roleName);
    }

    // Implementación del método findOrCreateAuth0User
    @Override
    public User findOrCreateAuth0User(String auth0Id, String email, Set<String> roles) { // 🛑 Modificado

        // 1. Determinar el TIPO DE USUARIO basándose en los roles del token
        boolean isClient = roles.contains("ROLE_CLIENT");

        if (isClient) {
            // --- Lógica para CLIENTE (Tienda Web) ---
            return handleClientProvisioning(auth0Id, email);

        } else {
            // --- Lógica para PERSONAL INTERNO (Admin, Vendedor, Proveedor) ---
            return handleUserProvisioning(auth0Id, email, roles);
        }
    }

    // 🛑 NUEVO: Método para el Provisioning de CLIENTES
    private User handleClientProvisioning(String auth0Id, String email) {
        // 1. Intentar encontrar el cliente por su ID de Auth0
        Optional<Client> existingClient = clientRepository.findByAuth0Id(auth0Id);

        if (existingClient.isPresent()) {
            // En un servicio real, aquí podrías devolver un objeto Client o una respuesta
            // Para simplificar, devolvemos null o un placeholder.
            // Pero el objetivo es que el CLIENTE EXISTA en su propia tabla.
            // NOTA: Para este servicio de AUTENTICACIÓN, puedes devolver un User vacío o lanzar una excepción,
            // ya que el front de Ventas/Tienda Web probablemente solo necesite saber que el JIT fue exitoso.
            System.out.println("Cliente ya existe en la BD. Provisioning JIT exitoso.");
            return null; // O un User nulo/dummy si tu interfaz lo requiere
        }

        // 2. Si no existe, crear un nuevo CLIENTE
        Client newClient = new Client();
        newClient.setAuth0Id(auth0Id);
        newClient.setEmail(email);
        newClient.setFullName(email); // O parsear el nombre si viene en la petición

        // 3. Guardar el nuevo cliente
        clientRepository.save(newClient);
        System.out.println("Nuevo Cliente creado en la BD. Provisioning JIT exitoso.");
        return null; // O un User nulo/dummy
    }

    // 🛑 NUEVO: Método para el Provisioning de PERSONAL (Trabajadores)
    private User handleUserProvisioning(String auth0Id, String email, Set<String> roleNames) {
        // 1. Intentar encontrar el usuario por su ID de Auth0
        Optional<User> existingUser = userRepository.findByAuth0Id(auth0Id);

        if (existingUser.isPresent()) {
            return existingUser.get();
        }

        // 2. Si no existe, crear un nuevo USUARIO (Trabajador)
        User newUser = new User();
        newUser.setAuth0Id(auth0Id);
        newUser.setUsername(email);
        newUser.setPassword(null);

        // 3. Asignar los roles (ej. ROLE_ADMIN, ROLE_VENDOR)
        Set<Role> roles = new HashSet<>();
        for (String roleName : roleNames) {
            roleRepository.findByName(roleName).ifPresent(roles::add);
        }

        if (roles.isEmpty()) {
            throw new RuntimeException("No se encontraron roles válidos en la BD para el usuario de Auth0.");
        }

        newUser.setRoles(roles);

        // 4. Guardar el nuevo usuario
        return userRepository.save(newUser);
    }
}
