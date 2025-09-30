package com.nomos.inventory.auth.service;

import com.nomos.inventory.auth.model.User;
import com.nomos.inventory.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthUserDetailsService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(AuthUserDetailsService.class);

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        // Mapea los roles de la entidad User a objetos GrantedAuthority de Spring Security
        Collection<? extends GrantedAuthority> authorities = user.getRoles().stream()
                // Asumimos que Role.getName() devuelve el nombre del rol (ej. "ROLE_ADMIN")
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());

        // LOG para verificar los roles que se cargan de la DB
        if (authorities.isEmpty()) {
            log.warn("El usuario {} no tiene roles asignados en la DB. Asignando ROLE_ADMIN por defecto temporalmente.", username);
            authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN"));
        } else {
            log.info("Roles cargados para el usuario {}: {}", username, authorities);
        }

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                authorities
        );
    }
}