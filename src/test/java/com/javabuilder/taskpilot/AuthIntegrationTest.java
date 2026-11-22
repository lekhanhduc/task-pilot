package com.javabuilder.taskpilot;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.javabuilder.taskpilot.dto.LoginRequest;
import com.javabuilder.taskpilot.model.AppUser;
import com.javabuilder.taskpilot.repository.AppUserRepository;
import com.javabuilder.taskpilot.repository.RefreshTokenRepository;
import com.javabuilder.taskpilot.security.JwtTokenProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final String EMAIL = "test@example.com";
    private static final String PASSWORD = "s3cr3tPassword";

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        userRepository.deleteAll();
        AppUser user = AppUser.builder()
                .email(EMAIL)
                .password(passwordEncoder.encode(PASSWORD))
                .roles(Set.of("USER"))
                .enabled(true)
                .accountNonLocked(true)
                .build();
        userRepository.save(user);
    }

    @Test
    void loginWithValidCredentials_returns200WithTokens() throws Exception {
        LoginRequest req = new LoginRequest(EMAIL, PASSWORD);
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andReturn();

        String body = result.getResponse().getContentAsString();
        @SuppressWarnings("unchecked")
        Map<String, Object> map = objectMapper.readValue(body, Map.class);
        assertThat(map.get("accessToken").toString()).isNotBlank();
        assertThat(map.get("refreshToken").toString()).isNotBlank();
    }

    @Test
    void accessTokenWorksOnProtectedEndpoint() throws Exception {
        LoginRequest req = new LoginRequest(EMAIL, PASSWORD);
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andReturn();

        @SuppressWarnings("unchecked")
        Map<String, Object> map = objectMapper.readValue(
                loginResult.getResponse().getContentAsString(), Map.class);
        String accessToken = map.get("accessToken").toString();

        mockMvc.perform(get("/api/ping")
                .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());
    }

    @Test
    void wrongPassword_returns401() throws Exception {
        LoginRequest req = new LoginRequest(EMAIL, "wrongPassword");
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }

    @Test
    void unknownEmail_returns401() throws Exception {
        LoginRequest req = new LoginRequest("unknown@example.com", PASSWORD);
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid email or password"));
    }

    @Test
    void missingEmail_returns400() throws Exception {
        String json = "{\"password\":\"somePass\"}";
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(json))
                .andExpect(status().isBadRequest());
    }

    @Test
    void blankPassword_returns400() throws Exception {
        LoginRequest req = new LoginRequest(EMAIL, "");
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void invalidEmailFormat_returns400() throws Exception {
        LoginRequest req = new LoginRequest("not-an-email", PASSWORD);
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginWithoutToken_isPublic() throws Exception {
        // /api/auth/login should not require a token - already tested above but let's be explicit
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LoginRequest(EMAIL, PASSWORD))))
                .andExpect(status().isOk());
    }

    @Test
    void refreshTokenIsStoredHashedInDb() throws Exception {
        LoginRequest req = new LoginRequest(EMAIL, PASSWORD);
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andReturn();

        @SuppressWarnings("unchecked")
        Map<String, Object> map = objectMapper.readValue(
                loginResult.getResponse().getContentAsString(), Map.class);
        String rawRefreshToken = map.get("refreshToken").toString();

        // The raw token should NOT be stored in the DB
        assertThat(refreshTokenRepository.findByTokenHash(rawRefreshToken)).isEmpty();

        // But there should be exactly one record and its hash should match via passwordEncoder
        assertThat(refreshTokenRepository.count()).isEqualTo(1);
        String storedHash = refreshTokenRepository.findAll().get(0).getTokenHash();
        assertThat(passwordEncoder.matches(rawRefreshToken, storedHash)).isTrue();
    }
}
