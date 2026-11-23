package com.javabuilder.taskpilot.service;

import com.javabuilder.taskpilot.common.TokenType;
import com.javabuilder.taskpilot.dto.response.LoginResponse;
import com.javabuilder.taskpilot.entity.RefreshToken;
import com.javabuilder.taskpilot.entity.User;
import com.javabuilder.taskpilot.exception.AccountDisabledException;
import com.javabuilder.taskpilot.exception.InvalidCredentialsException;
import com.javabuilder.taskpilot.repository.RefreshTokenRepository;
import com.javabuilder.taskpilot.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;

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

        String accessToken = jwtService.generateAccessToken(user);
        String rawRefreshToken = jwtService.generateRefreshToken();
        String tokenHash = hashToken(rawRefreshToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .tokenHash(tokenHash)
                .userId(user.getId())
                .expiresAt(Instant.now().plusSeconds(jwtService.getRefreshTokenTtlSeconds()))
                .build();
        refreshTokenRepository.save(refreshToken);

        return new LoginResponse(
                accessToken,
                rawRefreshToken,
                TokenType.BEARER.getValue(),
                jwtService.getAccessTokenTtlSeconds()
        );
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
