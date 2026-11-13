package com.valeerp.inventory.auth.service;

import com.valeerp.inventory.auth.model.User;
import com.valeerp.inventory.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthUserDetailsService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(AuthUserDetailsService.class);

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .or(() -> userRepository.findByEmail(username))
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        Set<GrantedAuthority> authorities = new HashSet<>();
        user.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getName())));
        user.effectivePermissionCodes()
                .forEach(code -> authorities.add(new SimpleGrantedAuthority(code)));

        if (authorities.isEmpty()) {
            log.warn("El usuario {} no tiene roles ni permisos asignados.", username);
        } else {
            log.info("Authorities cargadas para {}: {}", username, authorities);
        }

        String password = user.getPassword() == null ? "" : user.getPassword();
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                password,
                authorities
        );
    }
}
