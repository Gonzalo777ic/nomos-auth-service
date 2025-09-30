package com.nomos.inventory.auth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    // Utiliza una clave estática para evitar que cambie en cada reinicio
    private final Key key = Keys.hmacShaKeyFor("miClaveSecretaQueEsMuyLargaYSeguraParaUsarEnProduccion1234567890".getBytes(StandardCharsets.UTF_8));

    @Value("${jwt.expiration}")
    private Long expiration;

    // Retrieve username from token
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Retrieve expiration date from token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // NUEVO MÉTODO: Extrae la lista de roles del token
    public List<String> extractRoles(String token) {
        // El claim "roles" se almacena como List, pero Jackson/JPA lo lee como List<Object>.
        // Debemos castearlo a List<String>.
        List<?> rolesObject = extractAllClaims(token).get("roles", List.class);
        if (rolesObject == null) {
            return Collections.emptyList();
        }
        return rolesObject.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .collect(Collectors.toList());
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // Retrieve all claims from token
    private Claims extractAllClaims(String token) {
        Jws<Claims> claimsJws = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
        return claimsJws.getBody();
    }

    // Check if the token has expired
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // Método sobrecargado para incluir roles
    public String generateToken(String username, Collection<? extends GrantedAuthority> authorities) {
        // Convertir GrantedAuthority a una lista de Strings para el claim
        List<String> roleNames = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        log.info("Generando token JWT para usuario: {} con roles: {}", username, roleNames);

        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roleNames) // AÑADIDO: El claim de roles
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key)
                .compact();
    }

    // Método original, modificado para usar la versión con roles (por compatibilidad)
    public String generateToken(String username) {
        return generateToken(username, Collections.emptyList());
    }

    // Validate token
    public Boolean validateToken(String token, String username) {
        final String tokenUsername = extractUsername(token);
        return (tokenUsername.equals(username) && !isTokenExpired(token));
    }
}
