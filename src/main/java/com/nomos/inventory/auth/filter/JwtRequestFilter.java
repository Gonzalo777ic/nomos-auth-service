package com.nomos.inventory.auth.filter;

import com.nomos.inventory.auth.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtRequestFilter.class);

    // Ya no necesitamos AuthUserDetailsService porque leeremos los roles del JWT.
    // private final AuthUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            try {
                username = jwtUtil.extractUsername(jwt);
            } catch (Exception e) {
                // Capturar excepciones comunes de JWT (expiración, firma inválida)
                log.warn("Error al parsear el token JWT: {}", e.getMessage());
                // No se necesita hacer nada más, simplemente el usuario queda sin autenticar
            }
        }

        // Si el username fue extraído y no hay autenticación actual en el contexto
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // 1. Validar la firma y expiración del token
            if (jwtUtil.validateToken(jwt, username)) {

                // 2. Extraer roles del JWT (evitando la consulta a la base de datos)
                List<String> roles = jwtUtil.extractRoles(jwt);

                // Mapear los nombres de roles a objetos GrantedAuthority
                List<GrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                log.debug("Token válido para usuario {}. Roles asignados al contexto: {}", username, authorities);

                // 3. Crear el token de autenticación
                // Usamos el constructor con authorities para la autorización
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        username, // Usamos solo el username como principal
                        null,     // No se necesita la password
                        authorities);

                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 4. Establecer el usuario autenticado en el contexto de seguridad
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            } else {
                log.debug("Token JWT inválido para el usuario {}", username);
            }
        }
        chain.doFilter(request, response);
    }
}
