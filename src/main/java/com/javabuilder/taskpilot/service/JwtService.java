package com.javabuilder.taskpilot.service;

import com.javabuilder.taskpilot.configuration.JwtProperties;
import com.javabuilder.taskpilot.entity.User;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties jwtProperties;
    private final SecretKey jwtSecretKey;

    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(jwtProperties.accessTtl());

        String scope = String.join(" ", user.getRoles());

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(String.valueOf(user.getId()))
                .claim("scope", scope)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(exp))
                .build();

        return buildSignedToken(claims);
    }

    public String generateRefreshToken() {
        return UUID.randomUUID().toString() + UUID.randomUUID().toString();
    }

    public long getAccessTokenTtlSeconds() {
        return jwtProperties.accessTtl();
    }

    private String buildSignedToken(JWTClaimsSet claims) {
        try {
            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new MACSigner(jwtSecretKey.getEncoded()));
            return signedJWT.serialize();
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign JWT", e);
        }
    }
}
