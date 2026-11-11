package com.study.jwt.jwt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.study.jwt.user.Role;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * ⭐ 이 프로젝트의 핵심. JWT를 만들고(서명) 검증하는 전부.
 *
 * 학습용으로 라이브러리 없이 직접 구현했다. 실무에서는 jjwt / nimbus-jose-jwt 를 쓴다 (README 6장).
 * 라이브러리도 내부에서 하는 일은 아래와 똑같다.
 *
 * JWT = base64url(header) + "." + base64url(payload) + "." + base64url(signature)
 *       signature = HMAC-SHA256(비밀키, "header.payload")
 */
@Component
public class JwtProvider {

    private static final String ALGORITHM = "HS256";
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private final byte[] secret;
    private final JwtProperties properties;
    private final ObjectMapper objectMapper;

    public JwtProvider(JwtProperties properties, ObjectMapper objectMapper) {
        this.secret = properties.secret().getBytes(StandardCharsets.UTF_8);
        // HS256 키가 짧으면 무차별 대입으로 키를 알아낼 수 있다 → 최소 256비트
        if (secret.length < 32) {
            throw new IllegalStateException("jwt.secret은 최소 32바이트여야 한다");
        }
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public String createAccessToken(String email, Role role) {
        return createToken(email, role, TokenType.ACCESS, properties.accessTokenValidity());
    }

    public String createRefreshToken(String email, Role role) {
        return createToken(email, role, TokenType.REFRESH, properties.refreshTokenValidity());
    }

    // ===================== 1. 발급 (로그인할 때) =====================

    public String createToken(String email, Role role, TokenType type, Duration validity) {
        Instant now = Instant.now();

        Map<String, Object> header = Map.of("alg", ALGORITHM, "typ", "JWT");

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("sub", email);                    // 누구인지 (subject)
        payload.put("role", role.name());             // 권한 → 매 요청마다 DB를 안 봐도 인가 가능
        payload.put("type", type.name());             // ACCESS / REFRESH 구분
        payload.put("jti", UUID.randomUUID().toString()); // 토큰 고유 ID (같은 초에 발급해도 토큰이 달라짐)
        payload.put("iat", now.getEpochSecond());     // 발급 시각 (초)
        payload.put("exp", now.plus(validity).getEpochSecond()); // 만료 시각 (초)
        // ⚠️ payload는 암호화가 아니라 인코딩이다. 누구나 디코딩해서 읽을 수 있다 → 비밀번호·개인정보 넣지 말 것

        String signingInput = encode(header) + "." + encode(payload);
        return signingInput + "." + ENCODER.encodeToString(hmacSha256(signingInput));
    }

    // ===================== 2. 검증 (매 요청마다) =====================

    /**
     * 순서가 중요하다: ① 모양 → ② 알고리즘 → ③ 서명 → ④ 만료 → ⑤ claim 꺼내기.
     * 서명을 확인하기 전의 payload는 "아무나 써넣을 수 있는 글자"라서 믿으면 안 된다.
     */
    public JwtClaims verify(String token) {
        // ① 점(.)으로 나눈 3부분인가
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new InvalidTokenException("형식 오류: header.payload.signature 3부분이 아님");
        }

        // ② 우리가 쓰는 알고리즘인가 — alg:none 공격(서명 없이 통과시키기) 차단
        Map<String, Object> header = decode(parts[0]);
        if (!ALGORITHM.equals(header.get("alg"))) {
            throw new InvalidTokenException("허용하지 않는 알고리즘: " + header.get("alg"));
        }

        // ③ ⭐ 서명 검증: 서버가 가진 비밀키로 header.payload를 다시 서명해서, 토큰에 붙은 서명과 비교
        //    payload를 한 글자라도 바꾸면(예: role USER→ADMIN) 다시 계산한 서명이 달라진다.
        //    비밀키를 모르는 사람은 맞는 서명을 만들 수 없다. 이것이 "위조 불가"의 근거.
        byte[] expected = hmacSha256(parts[0] + "." + parts[1]);
        byte[] actual = decodeBytes(parts[2]);
        if (!MessageDigest.isEqual(expected, actual)) { // 비교 시간이 일정한 비교 (타이밍 공격 방지)
            throw new InvalidTokenException("서명 불일치: 변조됐거나 다른 키로 서명된 토큰");
        }

        // ④ 만료 확인 — 서명이 맞아도 exp가 지났으면 거부
        Map<String, Object> payload = decode(parts[1]);
        Instant expiresAt = Instant.ofEpochSecond(((Number) payload.get("exp")).longValue());
        if (!Instant.now().isBefore(expiresAt)) {
            throw new InvalidTokenException("만료된 토큰");
        }

        // ⑤ 여기까지 통과해야 비로소 payload 내용을 믿는다
        return new JwtClaims(
                (String) payload.get("sub"),
                Role.valueOf((String) payload.get("role")),
                TokenType.valueOf((String) payload.get("type")),
                (String) payload.get("jti"),
                Instant.ofEpochSecond(((Number) payload.get("iat")).longValue()),
                expiresAt);
    }

    // ===================== 내부 도구 =====================

    private byte[] hmacSha256(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private String encode(Map<String, Object> json) {
        try {
            return ENCODER.encodeToString(objectMapper.writeValueAsBytes(json));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private Map<String, Object> decode(String part) {
        try {
            return objectMapper.readValue(decodeBytes(part), new TypeReference<>() {});
        } catch (InvalidTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidTokenException("형식 오류: JSON으로 읽을 수 없음");
        }
    }

    private byte[] decodeBytes(String part) {
        try {
            return DECODER.decode(part);
        } catch (IllegalArgumentException e) {
            throw new InvalidTokenException("형식 오류: Base64URL이 아님");
        }
    }
}
