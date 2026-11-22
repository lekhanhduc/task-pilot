package com.javabuilder.taskpilot.security;

import com.javabuilder.taskpilot.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {

    private final SecretKey signingKey;
    private final long accessTtlSeconds;

    public JwtTokenProvider(JwtProperties props) {
        this.signingKey = Keys.hmacShaKeyFor(props.secret().getBytes(StandardCharsets.UTF_8));
        this.accessTtlSeconds = props.accessTtl();
    }

    public String generateAccessToken(Long userId, Collection<String> roles) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(accessTtlSeconds);
        return Jwts.builder()
                .subject(String.valueOf(userId))
                .claim("roles", List.copyOf(roles))
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .signWith(signingKey)
                .compact();
    }

    public long getAccessTtlSeconds() {
        return accessTtlSeconds;
    }

    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
