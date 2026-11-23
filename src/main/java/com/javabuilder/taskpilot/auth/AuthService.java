package com.javabuilder.taskpilot.auth;

import com.javabuilder.taskpilot.config.JwtProperties;
import com.javabuilder.taskpilot.user.User;
import com.javabuilder.taskpilot.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtEncoder jwtEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;

    public LoginResponse login(String email, String password) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        if (!user.isEnabled()) {
            throw new AccountDisabledException("Account is disabled");
        }

        if (!user.isAccountNonLocked()) {
            throw new AccountDisabledException("Account is locked");
        }

        Instant now = Instant.now();
        Instant accessExpiry = now.plusSeconds(jwtProperties.accessTtl());

        Set<String> roles = user.getRoles();
        String scope = String.join(" ", roles);

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(String.valueOf(user.getId()))
                .issuedAt(now)
                .expiresAt(accessExpiry)
                .claim("scope", scope)
                .build();

        String accessToken = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        String rawRefreshToken = UUID.randomUUID().toString() + UUID.randomUUID().toString();
        String tokenHash = hashToken(rawRefreshToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .tokenHash(tokenHash)
                .userId(user.getId())
                .expiresAt(now.plusSeconds(jwtProperties.refreshTtl()))
                .build();
        refreshTokenRepository.save(refreshToken);

        return new LoginResponse(accessToken, rawRefreshToken, "Bearer", jwtProperties.accessTtl());
    }

    private String hashToken(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }
}
