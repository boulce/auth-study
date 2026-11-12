package com.study.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 테스트용 가짜 Google. 진짜 Google이 우리 서버에게 해주는 3가지를 흉내낸다.
 *
 *   POST /token     : code를 받고 Access Token + ID Token(JWT)을 준다   (진짜: https://oauth2.googleapis.com/token)
 *   GET  /jwks      : ID Token 서명을 검증할 Google 공개키를 준다         (진짜: https://www.googleapis.com/oauth2/v3/certs)
 *   GET  /userinfo  : Access Token을 받고 프로필을 준다                   (진짜: https://openidconnect.googleapis.com/v1/userinfo)
 *
 * 브라우저가 보는 "Google 로그인 화면"은 흉내내지 않는다. 그 화면의 결과(code, state를 들고 돌아오기)를 테스트가 직접 재현한다.
 */
class FakeGoogleServer {

    static final String ISSUER = "https://accounts.google.com";
    static final String ACCESS_TOKEN = "fake-google-access-token";

    /** Google의 서명 키. 개인키는 Google만, 공개키는 /jwks로 누구에게나 공개 (RS256) */
    private final RSAKey googleKey = generateKey("google-key");
    /** 공격자가 만든 키. 이 키로 서명한 ID Token은 Google 공개키로 검증하면 실패해야 한다 */
    private final RSAKey attackerKey = generateKey("attacker-key");

    private final String clientId;
    private final HttpServer server;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final List<TokenRequest> tokenRequests = new CopyOnWriteArrayList<>();

    private volatile NextLogin next;

    /** 우리 서버가 /token에 보낸 요청 (back channel 확인용) */
    record TokenRequest(String authorizationHeader, String body) {
    }

    private record NextLogin(String sub, String email, String name, String nonce, boolean forged) {
    }

    FakeGoogleServer(String clientId) {
        this.clientId = clientId;
        try {
            server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        server.createContext("/token", this::token);
        server.createContext("/jwks", exchange -> respond(exchange, new JWKSet(googleKey.toPublicJWK()).toString()));
        server.createContext("/userinfo", this::userInfo);
        server.start();
    }

    String baseUrl() {
        return "http://localhost:" + server.getAddress().getPort();
    }

    /** "사용자가 Google에서 이 계정으로 로그인했다"고 정해둔다. nonce는 우리 서버가 인가 요청에 붙였던 값 */
    void willLogin(String sub, String email, String name, String nonce) {
        next = new NextLogin(sub, email, name, nonce, false);
    }

    /** 다음 ID Token을 Google 키가 아닌 공격자 키로 서명한다 */
    void willReturnForgedIdToken(String sub, String email, String name, String nonce) {
        next = new NextLogin(sub, email, name, nonce, true);
    }

    TokenRequest lastTokenRequest() {
        return tokenRequests.get(tokenRequests.size() - 1);
    }

    int tokenRequestCount() {
        return tokenRequests.size();
    }

    void stop() {
        server.stop(0);
    }

    // ---- 엔드포인트 ----

    private void token(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        tokenRequests.add(new TokenRequest(exchange.getRequestHeaders().getFirst("Authorization"), body));

        respond(exchange, objectMapper.writeValueAsString(Map.of(
                "access_token", ACCESS_TOKEN,
                "token_type", "Bearer",
                "expires_in", 3600,
                "scope", "openid profile email",
                "id_token", idToken(next))));
    }

    private void userInfo(HttpExchange exchange) throws IOException {
        if (!("Bearer " + ACCESS_TOKEN).equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
            exchange.sendResponseHeaders(401, -1);
            exchange.close();
            return;
        }
        respond(exchange, objectMapper.writeValueAsString(Map.of(
                "sub", next.sub(), "email", next.email(), "email_verified", true, "name", next.name())));
    }

    /** Google이 발급하는 ID Token과 같은 모양의 JWT */
    private String idToken(NextLogin login) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)                // 누가 발급했나 → 우리 서버가 accounts.google.com인지 확인
                .audience(clientId)            // 누구에게 발급했나 → 우리 client-id인지 확인 (다른 앱용 토큰 재사용 방지)
                .subject(login.sub())          // Google 사용자 고유 ID
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(3600)))
                .claim("nonce", login.nonce()) // 우리 서버가 보낸 nonce 그대로 → 재전송(replay) 방지
                .claim("email", login.email())
                .claim("email_verified", true)
                .claim("name", login.name())
                .build();

        RSAKey key = login.forged() ? attackerKey : googleKey;
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void respond(HttpExchange exchange, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static RSAKey generateKey(String keyId) {
        try {
            return new RSAKeyGenerator(2048).keyID(keyId).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }
}
