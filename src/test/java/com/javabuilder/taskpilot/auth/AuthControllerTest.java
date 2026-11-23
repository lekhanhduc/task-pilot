package com.javabuilder.taskpilot.auth;

import com.javabuilder.taskpilot.entity.User;
import com.javabuilder.taskpilot.repository.UserRepository;
import com.javabuilder.taskpilot.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private static final String TEST_EMAIL = "test@example.com";
    private static final String TEST_PASSWORD = "secret123";

    @BeforeEach
    void setUp() {
        User user = User.builder()
                .email(TEST_EMAIL)
                .password(passwordEncoder.encode(TEST_PASSWORD))
                .roles(Set.of("ROLE_USER"))
                .enabled(true)
                .accountNonLocked(true)
                .build();
        userRepository.save(user);
    }

    @Test
    void validCredentials_returns200WithTokens() throws Exception {
        String body = "{\"email\":\"" + TEST_EMAIL + "\",\"password\":\"" + TEST_PASSWORD + "\"}";

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andReturn();

        String responseJson = result.getResponse().getContentAsString();
        assertThat(responseJson).contains("accessToken");
        assertThat(responseJson).contains("refreshToken");
    }

    @Test
    void accessTokenIsAcceptedByResourceServer() throws Exception {
        String body = "{\"email\":\"" + TEST_EMAIL + "\",\"password\":\"" + TEST_PASSWORD + "\"}";

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isOk())
                .andReturn();

        String responseJson = loginResult.getResponse().getContentAsString();
        // Extract accessToken from JSON manually to avoid Jackson version issues
        String accessToken = extractField(responseJson, "accessToken");

        mockMvc.perform(get("/api/hello")
                .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());
    }

    @Test
    void wrongPassword_returns401() throws Exception {
        String body = "{\"email\":\"" + TEST_EMAIL + "\",\"password\":\"wrongpassword\"}";

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid email or password"));
    }

    @Test
    void unknownEmail_returns401WithSameMessage() throws Exception {
        String body = "{\"email\":\"unknown@example.com\",\"password\":\"" + TEST_PASSWORD + "\"}";

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid email or password"));
    }

    @Test
    void missingEmail_returns400() throws Exception {
        String body = "{\"password\":\"secret123\"}";

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void blankPassword_returns400() throws Exception {
        String body = "{\"email\":\"test@example.com\",\"password\":\"\"}";

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginWorksWithoutToken() throws Exception {
        String body = "{\"email\":\"" + TEST_EMAIL + "\",\"password\":\"" + TEST_PASSWORD + "\"}";

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isOk());
    }

    @Test
    void refreshTokenIsStoredHashedInDatabase() throws Exception {
        String body = "{\"email\":\"" + TEST_EMAIL + "\",\"password\":\"" + TEST_PASSWORD + "\"}";

        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isOk())
                .andReturn();

        String responseJson = loginResult.getResponse().getContentAsString();
        String rawRefreshToken = extractField(responseJson, "refreshToken");

        // Verify that the raw token is NOT stored in the DB
        List<com.javabuilder.taskpilot.entity.RefreshToken> tokens = refreshTokenRepository.findAll();
        assertThat(tokens).hasSize(1);
        assertThat(tokens.get(0).getTokenHash()).isNotEqualTo(rawRefreshToken);

        // Verify the hash matches what we expect
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(rawRefreshToken.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String expectedHash = java.util.Base64.getEncoder().encodeToString(hash);
        assertThat(tokens.get(0).getTokenHash()).isEqualTo(expectedHash);
    }

    @Test
    void disabledAccount_returns403() throws Exception {
        User disabledUser = User.builder()
                .email("disabled@example.com")
                .password(passwordEncoder.encode("password"))
                .roles(Set.of("ROLE_USER"))
                .enabled(false)
                .accountNonLocked(true)
                .build();
        userRepository.save(disabledUser);

        String body = "{\"email\":\"disabled@example.com\",\"password\":\"password\"}";

        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
                .andExpect(status().isForbidden());
    }

    private String extractField(String json, String fieldName) {
        String key = "\"" + fieldName + "\":\"";
        int start = json.indexOf(key);
        if (start == -1) throw new IllegalArgumentException("Field not found: " + fieldName);
        start += key.length();
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }
}
