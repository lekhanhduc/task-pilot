package com.javabuilder.taskpilot.service;

import com.javabuilder.taskpilot.configuration.JwtConfiguration;
import com.javabuilder.taskpilot.configuration.JwtProperties;
import com.javabuilder.taskpilot.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private static final String HEX_SECRET = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private static final long ACCESS_TTL = 900L;
    private static final long REFRESH_TTL = 604800L;

    private JwtService jwtService;
    private JwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        JwtProperties props = new JwtProperties(HEX_SECRET, ACCESS_TTL, REFRESH_TTL);
        byte[] keyBytes = hexStringToByteArray(HEX_SECRET);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "HmacSHA256");
        jwtService = new JwtService(props, secretKey);
        jwtDecoder = NimbusJwtDecoder.withSecretKey(secretKey).build();
    }

    @Test
    void generateAccessToken_isHS256() throws Exception {
        User user = buildUser();
        String token = jwtService.generateAccessToken(user);

        // Parse the header to verify algorithm
        String[] parts = token.split("\\.");
        assertThat(parts).hasSize(3);
        String headerJson = new String(java.util.Base64.getUrlDecoder().decode(parts[0]));
        assertThat(headerJson).contains("HS256");
    }

    @Test
    void generateAccessToken_containsSubAndRolesAndIatAndExp() {
        User user = buildUser();
        String token = jwtService.generateAccessToken(user);

        Jwt decoded = jwtDecoder.decode(token);

        assertThat(decoded.getSubject()).isEqualTo("1");
        assertThat(decoded.getClaimAsString("scope")).contains("ROLE_USER");
        assertThat(decoded.getIssuedAt()).isNotNull();
        assertThat(decoded.getExpiresAt()).isNotNull();
    }

    @Test
    void generateAccessToken_expEqualsIatPlusTtl() {
        User user = buildUser();
        String token = jwtService.generateAccessToken(user);

        Jwt decoded = jwtDecoder.decode(token);

        long iat = decoded.getIssuedAt().getEpochSecond();
        long exp = decoded.getExpiresAt().getEpochSecond();
        assertThat(exp - iat).isEqualTo(ACCESS_TTL);
    }

    @Test
    void generateAccessToken_canBeDecodedByJwtDecoder() {
        User user = buildUser();
        String token = jwtService.generateAccessToken(user);

        // Should not throw
        Jwt decoded = jwtDecoder.decode(token);
        assertThat(decoded).isNotNull();
    }

    @Test
    void generateRefreshToken_returnsNonBlankString() {
        String rt = jwtService.generateRefreshToken();
        assertThat(rt).isNotBlank();
    }

    @Test
    void getAccessTokenTtlSeconds_returnsConfiguredValue() {
        assertThat(jwtService.getAccessTokenTtlSeconds()).isEqualTo(ACCESS_TTL);
    }

    private User buildUser() {
        return User.builder()
                .id(1L)
                .email("user@example.com")
                .password("encoded")
                .roles(Set.of("ROLE_USER"))
                .enabled(true)
                .accountNonLocked(true)
                .build();
    }

    private static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
