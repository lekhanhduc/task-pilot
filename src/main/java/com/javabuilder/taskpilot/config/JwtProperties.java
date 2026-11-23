package com.javabuilder.taskpilot.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
        String secret,
        long accessTtl,
        long refreshTtl
) {
}
