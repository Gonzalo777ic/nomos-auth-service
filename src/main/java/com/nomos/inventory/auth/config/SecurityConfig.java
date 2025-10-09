package com.nomos.inventory.auth.config;

import com.nomos.inventory.auth.filter.JwtRequestFilter;
import com.nomos.inventory.auth.service.AuthUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.beans.factory.annotation.Value;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtRequestFilter jwtRequestFilter;
    private final AuthUserDetailsService authUserDetailsService;

    @Bean
    public UserDetailsService userDetailsService() {
        return authUserDetailsService;
    }

    // Inyectar el Issuer URI y Audience para la validación de JWT (vienen del application.properties)
    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    /**
     * Cadena de filtros de seguridad para endpoints públicos.
     * Esta cadena tiene la menor prioridad (Order(1)), por lo que se ejecuta primero.
     * Permite el acceso sin autenticación a la ruta /api/auth/**.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain publicFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .securityMatcher("/api/auth/**")
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());

        return http.build();
    }

    // NUEVO: Bean para configurar el mapeo de Roles de Auth0
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        // 1. Define un convertidor de autoridades que mapea el claim estándar de scopes/roles
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

        // 2. Define el nombre del claim personalizado donde Auth0 inyectó los roles
        // Esto coincide con el prefijo que usaste en la Auth0 Action.
        grantedAuthoritiesConverter.setAuthoritiesClaimName("https://nomos.inventory.api/roles");

        // 3. Define un prefijo de autoridad para que Spring Security lo reconozca
        // (Dejamos el prefijo vacío o en blanco para que Spring no agregue "SCOPE_" o "ROLE_" si no lo queremos)
        grantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        // Asignar el convertidor personalizado de autoridades
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    // NUEVA CADENA DE FILTROS: Maneja la autenticación de Auth0 (Sales Front)
    @Bean
    @Order(2)
    public SecurityFilterChain auth0FilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .securityMatcher("/api/sales/**")
                .authorizeHttpRequests(auth -> auth
                        // Ahora, Spring Security buscará "ROLE_CLIENT" en el token gracias al converter.
                        // Solo permitimos el acceso si tienen el rol de cliente.
                        .anyRequest().hasAuthority("ROLE_CLIENT")
                )
                // Habilitar el Resource Server (Auth0 JWT validation)
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt
                        // 🔑 Aplicar el convertidor de claims para que Spring lea el rol del token
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())
                ))
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    /**
     * Cadena de filtros de seguridad para endpoints protegidos LOCALES (Inventory Front).
     * Nota: Ahora tiene Order(3) implícito o explícito si se lo añades.
     */

    /**
     * Cadena de filtros de seguridad para endpoints protegidos, ahora con autorización por roles.
     */
    @Bean
    public SecurityFilterChain protectedFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        // Nueva regla: Solo usuarios con ROLE_ADMIN pueden acceder a esta ruta.
                        // Usamos hasAuthority porque el rol fue insertado como una autoridad SimpleGrantedAuthority.
                        .requestMatchers("/api/test/admin").hasAuthority("ROLE_ADMIN")
                        // El resto de peticiones requieren cualquier usuario autenticado (con o sin rol específico)
                        .anyRequest().authenticated()
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:8081"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    @Bean
    public JwtDecoder jwtDecoder() {
        // Usa el Issuer URI configurado para construir el decodificador
        return NimbusJwtDecoder.withJwkSetUri(issuerUri + ".well-known/jwks.json").build();
    }

}