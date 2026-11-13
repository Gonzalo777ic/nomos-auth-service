package com.valeerp.inventory.auth.util;

import com.valeerp.inventory.auth.acl.AclProperties;
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

    private final Key key = Keys.hmacShaKeyFor(
            "miClaveSecretaQueEsMuyLargaYSeguraParaUsarEnProduccion1234567890".getBytes(StandardCharsets.UTF_8)
    );

    private final AclProperties aclProperties;

    @Value("${jwt.expiration}")
    private Long expiration;

    public JwtUtil(AclProperties aclProperties) {
        this.aclProperties = aclProperties;
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public List<String> extractRoles(String token) {
        return extractStringListClaim(token, aclProperties.getRolesClaim());
    }

    public List<String> extractPermissions(String token) {
        return extractStringListClaim(token, aclProperties.getPermissionsClaim());
    }

    public List<String> extractGroups(String token) {
        return extractStringListClaim(token, aclProperties.getGroupsClaim());
    }

    private List<String> extractStringListClaim(String token, String claimName) {
        List<?> values = extractAllClaims(token).get(claimName, List.class);
        if (values == null) {
            return Collections.emptyList();
        }
        return values.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .collect(Collectors.toList());
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        Jws<Claims> claimsJws = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
        return claimsJws.getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(String username, Collection<? extends GrantedAuthority> authorities) {
        return generateToken(username, authorities, List.of(), List.of(), List.of());
    }

    public String generateToken(
            String username,
            Collection<? extends GrantedAuthority> authorities,
            List<String> permissions,
            List<String> groups,
            List<String> menuKeys
    ) {
        List<String> roleNames = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .collect(Collectors.toList());

        log.info("Generando token JWT para usuario: {} con roles: {} permisos: {}",
                username, roleNames, permissions);

        return Jwts.builder()
                .setSubject(username)
                .claim(aclProperties.getRolesClaim(), roleNames)
                .claim(aclProperties.getPermissionsClaim(), permissions == null ? List.of() : permissions)
                .claim(aclProperties.getGroupsClaim(), groups == null ? List.of() : groups)
                .claim(aclProperties.getMenusClaim(), menuKeys == null ? List.of() : menuKeys)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key)
                .compact();
    }

    public String generateToken(String username) {
        return generateToken(username, Collections.emptyList());
    }

    public Boolean validateToken(String token, String username) {
        final String tokenUsername = extractUsername(token);
        return (tokenUsername.equals(username) && !isTokenExpired(token));
    }
}
