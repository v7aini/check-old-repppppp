package com.cybersec.shared.auth;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger log = LoggerFactory.getLogger(JwtUtils.class);
    @Value("${app.jwt.secret}") private String secret;
    @Value("${app.jwt.expiration-ms}") private int expirationMs;

    private Key key() { return Keys.hmacShaKeyFor(secret.getBytes()); }

    public String generateToken(String username, String role) {
        return Jwts.builder().setSubject(username).claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(key(), SignatureAlgorithm.HS256).compact();
    }

    public String getUsername(String token) {
        return Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validate(String token) {
        try { Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(token); return true; }
        catch (Exception e) { log.debug("[JWT] invalid: {}", e.getMessage()); return false; }
    }
}
