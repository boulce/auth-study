package com.study.jwt.auth;

/** 로그인·재발급 응답 body. session-demo의 Set-Cookie 대신 이걸 클라이언트가 직접 보관한다 */
public record TokenResponse(
        String tokenType,
        String accessToken,
        long accessTokenExpiresIn,
        String refreshToken
) {
}
