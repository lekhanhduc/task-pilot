package com.javabuilder.taskpilot.service;

import com.javabuilder.taskpilot.config.JwtProperties;
import com.javabuilder.taskpilot.dto.LoginRequest;
import com.javabuilder.taskpilot.dto.LoginResponse;
import com.javabuilder.taskpilot.model.AppUser;
import com.javabuilder.taskpilot.model.RefreshToken;
import com.javabuilder.taskpilot.repository.AppUserRepository;
import com.javabuilder.taskpilot.repository.RefreshTokenRepository;
import com.javabuilder.taskpilot.security.JwtTokenProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Service
public class AuthService {

    private static final int REFRESH_TOKEN_BYTES = 32;

    private final AppUserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final JwtProperties jwtProperties;
    private final SecureRandom secureRandom = new SecureRandom();

    public AuthService(AppUserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       JwtTokenProvider tokenProvider,
                       PasswordEncoder passwordEncoder,
                       JwtProperties jwtProperties) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenProvider = tokenProvider;
        this.passwordEncoder = passwordEncoder;
        this.jwtProperties = jwtProperties;
    }

    @Transactional
    public LoginResponse login(LoginRequest request) {
        AppUser user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (!user.isEnabled()) {
            throw new DisabledException("Account is disabled");
        }
        if (!user.isAccountNonLocked()) {
            throw new LockedException("Account is locked");
        }

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BadCredentialsException("Invalid email or password");
        }

        String accessToken = tokenProvider.generateAccessToken(user.getId(), user.getRoles());

        // generate opaque refresh token
        byte[] raw = new byte[REFRESH_TOKEN_BYTES];
        secureRandom.nextBytes(raw);
        String rawRefreshToken = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

        // hash before storing
        String hashed = passwordEncoder.encode(rawRefreshToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .tokenHash(hashed)
                .user(user)
                .expiresAt(Instant.now().plusSeconds(jwtProperties.refreshTtl()))
                .build();
        refreshTokenRepository.save(refreshToken);

        return new LoginResponse(
                accessToken,
                rawRefreshToken,
                "Bearer",
                tokenProvider.getAccessTtlSeconds());
    }
}
