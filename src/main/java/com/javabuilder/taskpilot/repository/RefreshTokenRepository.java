package com.javabuilder.taskpilot.repository;

import com.javabuilder.taskpilot.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
}
