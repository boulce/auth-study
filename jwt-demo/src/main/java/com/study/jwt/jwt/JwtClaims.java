package com.study.jwt.jwt;

import com.study.jwt.user.Role;

import java.time.Instant;

/** 서명·만료 검증을 통과한 payload. 이 객체가 만들어졌다 = 믿어도 되는 정보 */
public record JwtClaims(
        String email,
        Role role,
        TokenType type,
        String jti,
        Instant issuedAt,
        Instant expiresAt
) {
}
