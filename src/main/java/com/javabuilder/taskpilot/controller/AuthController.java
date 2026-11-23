package com.javabuilder.taskpilot.controller;

import com.javabuilder.taskpilot.dto.request.LoginRequest;
import com.javabuilder.taskpilot.dto.response.LoginResponse;
import com.javabuilder.taskpilot.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request.email(), request.password());
        return ResponseEntity.ok(response);
    }
}
