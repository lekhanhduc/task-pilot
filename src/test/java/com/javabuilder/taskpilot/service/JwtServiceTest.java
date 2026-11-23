package com.javabuilder.taskpilot.service;

import com.javabuilder.taskpilot.configuration.JwtConfiguration;
import com.javabuilder.taskpilot.configuration.JwtProperties;
import com.javabuilder.taskpilot.entity.User;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class JwtServiceTest {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private JwtProperties jwtProperties;

    @Test
    void generateAccessToken_isHS256AndContainsExpectedClaims() throws Exception {
        User user = User.builder()
                .id(42L)
                .email("user@example.com")
                .password("encoded")
                .roles(Set.of("ROLE_USER"))
                .build();

        String token = jwtService.generateAccessToken(user);

        // Parse the token header to verify algorithm
        SignedJWT signedJWT = SignedJWT.parse(token);
        assertThat(signedJWT.getHeader().getAlgorithm().getName()).isEqualTo("HS256");

        // Verify claims via raw parse
        var claims = signedJWT.getJWTClaimsSet();
        assertThat(claims.getSubject()).isEqualTo("42");
        assertThat(claims.getClaim("scope").toString()).contains("ROLE_USER");
        assertThat(claims.getIssueTime()).isNotNull();
        assertThat(claims.getExpirationTime()).isNotNull();

        // exp == iat + ttl
        long iat = claims.getIssueTime().toInstant().getEpochSecond();
        long exp = claims.getExpirationTime().toInstant().getEpochSecond();
        assertThat(exp - iat).isEqualTo(jwtProperties.accessTtl());

        // Token can be decoded by JwtDecoder (resource server)
        Jwt decodedJwt = jwtDecoder.decode(token);
        assertThat(decodedJwt.getSubject()).isEqualTo("42");
        assertThat(decodedJwt.getClaim("scope").toString()).contains("ROLE_USER");
    }
}
