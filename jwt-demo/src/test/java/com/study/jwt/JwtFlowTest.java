package com.study.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.study.jwt.jwt.JwtProvider;
import com.study.jwt.jwt.TokenType;
import com.study.jwt.user.Role;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * session-demo의 SessionFlowTest와 같은 시나리오를 JWT로.
 * 차이: 쿠키 대신 클라이언트가 토큰을 직접 들고 "Authorization: Bearer ..." 헤더에 붙인다.
 * 1번 테스트를 위에서부터 읽으면 JWT 로그인의 전체 흐름, 2~4번은 공격 방어, 5~7번은 Refresh와 JWT의 한계.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class JwtFlowTest {

    @Autowired
    TestRestTemplate rest;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    JwtProvider jwtProvider;

    @Test
    void JWT_로그인_전체_흐름() throws Exception {
        // 1) 회원가입 (session-demo와 동일)
        assertThat(post("/api/auth/signup", Map.of("email", "user@test.com", "password", "password123"), null)
                .getStatusCode()).isEqualTo(HttpStatus.CREATED);

        // 2) 토큰 없이 보호된 API → 401
        ResponseEntity<String> noToken = get("/api/me", null);
        assertThat(noToken.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(noToken.getBody()).isEqualTo("토큰 없음");

        // 3) 로그인 성공 → body에 토큰 2개. ⭐ Set-Cookie(JSESSIONID)가 없다 = 서버에 세션이 안 생김
        ResponseEntity<String> login = login("user@test.com", "password123");
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(login.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();

        JsonNode tokens = objectMapper.readTree(login.getBody());
        assertThat(tokens.get("tokenType").asText()).isEqualTo("Bearer");
        assertThat(tokens.get("accessTokenExpiresIn").asLong()).isEqualTo(15 * 60);
        String accessToken = tokens.get("accessToken").asText();
        assertThat(accessToken.split("\\.")).hasSize(3); // header.payload.signature

        // 4) Authorization: Bearer <access> → 서버가 서명 검증만으로 누군지 앎 → 200
        ResponseEntity<String> me = get("/api/me", accessToken);
        assertThat(me.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(me.getBody()).contains("user@test.com").contains("ROLE_USER");
        assertThat(me.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();

        // 5) USER가 관리자 API → 403 (토큰은 유효, 권한 부족)
        assertThat(get("/api/admin/hello", accessToken).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // 6) ADMIN 토큰이면 → 200
        String adminToken = accessTokenOf(login("admin@test.com", "admin1234"));
        assertThat(get("/api/admin/hello", adminToken).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void 토큰은_암호화가_아니라_인코딩이라_누구나_payload를_읽을_수_있다() throws Exception {
        signup("readable@test.com");
        String accessToken = accessTokenOf(login("readable@test.com", "password123"));

        // 비밀키 없이 Base64URL 디코딩만 했는데 내용이 다 보인다 → 비밀번호·개인정보를 넣으면 안 되는 이유
        String payloadJson = new String(Base64.getUrlDecoder().decode(accessToken.split("\\.")[1]), StandardCharsets.UTF_8);
        assertThat(payloadJson)
                .contains("\"sub\":\"readable@test.com\"")
                .contains("\"role\":\"USER\"")
                .contains("\"exp\"")
                .doesNotContain("password");
    }

    @Test
    void payload를_변조하면_서명이_안맞아_401() throws Exception {
        signup("attacker@test.com");
        String accessToken = accessTokenOf(login("attacker@test.com", "password123"));
        String[] parts = accessToken.split("\\.");

        // 공격: payload의 role을 USER → ADMIN으로 바꾸고, 원래 서명은 그대로 붙인다
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String forgedPayload = base64Url(payloadJson.replace("\"role\":\"USER\"", "\"role\":\"ADMIN\""));
        String forged = parts[0] + "." + forgedPayload + "." + parts[2];

        // 403이 아니라 401: 권한 검사까지 가지도 못하고 "누군지 모름"으로 거부된다
        ResponseEntity<String> response = get("/api/admin/hello", forged);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).contains("서명 불일치");
    }

    @Test
    void alg_none_공격은_거부된다() {
        // 공격: "서명 안 함(alg:none)"이라고 써서 서명 없이 ADMIN 토큰을 만든다.
        // 서버가 header의 alg를 그대로 믿는 구현이면 통과돼 버린다 → 서버가 허용할 알고리즘을 고정해야 함
        String header = base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = base64Url("{\"sub\":\"admin@test.com\",\"role\":\"ADMIN\",\"type\":\"ACCESS\",\"exp\":9999999999}");
        String unsigned = header + "." + payload + ".";

        ResponseEntity<String> response = get("/api/admin/hello", unsigned);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).contains("허용하지 않는 알고리즘");
    }

    @Test
    void 만료된_토큰은_서명이_맞아도_401() {
        signup("expired@test.com");
        // 진짜 비밀키로 서명했지만 이미 1초 전에 만료된 토큰
        String expired = jwtProvider.createToken("expired@test.com", Role.USER, TokenType.ACCESS, Duration.ofSeconds(-1));

        ResponseEntity<String> response = get("/api/me", expired);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).contains("만료된 토큰"); // 클라이언트는 이걸 보고 /refresh를 부른다
    }

    @Test
    void Refresh로_재발급하면_둘_다_새로_바뀌고_예전_Refresh를_다시_쓰면_전부_폐기된다() throws Exception {
        signup("refresh@test.com");
        JsonNode first = objectMapper.readTree(login("refresh@test.com", "password123").getBody());
        String refresh1 = first.get("refreshToken").asText();

        // Refresh Token으로는 API를 못 부른다 (용도가 다름)
        assertThat(get("/api/me", refresh1).getBody()).contains("Refresh Token으로는 API를 호출할 수 없음");

        // 1) 재발급 → 새 Access + 새 Refresh (Rotation)
        ResponseEntity<String> refreshed = post("/api/auth/refresh", Map.of("refreshToken", refresh1), null);
        assertThat(refreshed.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode second = objectMapper.readTree(refreshed.getBody());
        String refresh2 = second.get("refreshToken").asText();
        assertThat(refresh2).isNotEqualTo(refresh1);
        assertThat(get("/api/me", second.get("accessToken").asText()).getStatusCode()).isEqualTo(HttpStatus.OK);

        // 2) ⭐ 예전 Refresh(refresh1)를 누가 다시 쓴다 → 탈취로 간주 → 401 + 서버의 Refresh 폐기
        ResponseEntity<String> reuse = post("/api/auth/refresh", Map.of("refreshToken", refresh1), null);
        assertThat(reuse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(reuse.getBody()).contains("재사용 감지");

        // 3) 그래서 정상 사용자의 최신 Refresh(refresh2)도 막힌다 → 다시 로그인해야 함
        assertThat(post("/api/auth/refresh", Map.of("refreshToken", refresh2), null).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void 로그아웃하면_Refresh는_막히지만_Access는_만료까지_살아있다_JWT의_한계() throws Exception {
        signup("logout@test.com");
        JsonNode tokens = objectMapper.readTree(login("logout@test.com", "password123").getBody());
        String accessToken = tokens.get("accessToken").asText();
        String refreshToken = tokens.get("refreshToken").asText();

        // 로그아웃 → 서버 DB의 Refresh 삭제
        assertThat(post("/api/auth/logout", Map.of(), accessToken).getStatusCode()).isEqualTo(HttpStatus.OK);

        // Refresh는 서버에 없으니 재발급 불가 → 401 ✅
        ResponseEntity<String> refresh = post("/api/auth/refresh", Map.of("refreshToken", refreshToken), null);
        assertThat(refresh.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(refresh.getBody()).contains("폐기된 Refresh Token");

        // ⭐ 그런데 Access는 여전히 200. 서버가 Access를 저장하지 않으니 지울 것도 없다.
        //    session-demo 9)번(로그아웃 후 같은 쿠키 → 401)과 정반대. 그래서 Access 만료를 짧게(15분) 잡는다.
        //    즉시 막아야 하면: Access의 jti를 Redis 블랙리스트에 넣고 필터에서 확인 (= 결국 상태를 다시 가짐)
        assertThat(get("/api/me", accessToken).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // ---- 클라이언트 흉내: 토큰을 직접 들고 Authorization 헤더에 붙인다 ----

    private void signup(String email) {
        post("/api/auth/signup", Map.of("email", email, "password", "password123"), null);
    }

    private ResponseEntity<String> login(String email, String password) {
        return post("/api/auth/login", Map.of("email", email, "password", password), null);
    }

    private String accessTokenOf(ResponseEntity<String> loginResponse) throws Exception {
        return objectMapper.readTree(loginResponse.getBody()).get("accessToken").asText();
    }

    private ResponseEntity<String> post(String url, Map<String, String> body, String accessToken) {
        return rest.exchange(url, HttpMethod.POST, new HttpEntity<>(body, headers(accessToken)), String.class);
    }

    private ResponseEntity<String> get(String url, String accessToken) {
        return rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers(accessToken)), String.class);
    }

    private HttpHeaders headers(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN));
        if (accessToken != null) {
            headers.setBearerAuth(accessToken); // Authorization: Bearer eyJ...
        }
        return headers;
    }

    private static String base64Url(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
