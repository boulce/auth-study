package com.study.jwt.auth;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * 서버가 저장하는 유일한 것. Access Token은 저장하지 않는다.
 *
 * 왜 Refresh만 저장하나? → Refresh는 수명이 길어서(14일) 탈취되면 위험하다.
 * 서버에 있어야 "로그아웃 = 삭제", "탈취 의심 = 폐기"가 가능하다.
 *
 * 학습용 단순화: 사용자당 1개(기기 1대). 실무에서는
 *  - Redis에 TTL과 함께 저장 (만료되면 자동 삭제, 빠름)
 *  - 원문 대신 해시를 저장 (DB가 털려도 토큰을 바로 못 씀)
 *  - 기기별로 여러 개 저장
 */
@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    private String email;

    @Column(nullable = false, length = 512)
    private String token;

    @Column(nullable = false)
    private Instant expiresAt;

    protected RefreshToken() {
    }

    public RefreshToken(String email, String token, Instant expiresAt) {
        this.email = email;
        this.token = token;
        this.expiresAt = expiresAt;
    }

    /** Rotation: 재발급할 때마다 새 Refresh로 갈아끼운다 → 예전 Refresh는 그 순간부터 무효 */
    public void rotate(String newToken, Instant newExpiresAt) {
        this.token = newToken;
        this.expiresAt = newExpiresAt;
    }

    public String getEmail() { return email; }
    public String getToken() { return token; }
    public Instant getExpiresAt() { return expiresAt; }
}
