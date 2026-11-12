package com.study.oauth2;

import com.study.oauth2.user.Role;
import com.study.oauth2.user.User;
import com.study.oauth2.user.UserRepository;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Google 로그인(OAuth2 Authorization Code + OIDC)을 브라우저 대신 손으로 한 단계씩 재현한다.
 * 1번 테스트를 위에서부터 읽으면 전체 흐름. 2~3번은 공격 방어, 4번은 회원 연결.
 *
 * 등장인물
 *   브라우저(사용자)  = 이 테스트
 *   우리 서버(Client) = Spring 앱 (oauth2-demo)
 *   Google            = FakeGoogleServer (토큰·공개키·프로필 담당) + Google 로그인 화면(테스트가 결과만 재현)
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OAuth2FlowTest {

    static final String CLIENT_ID = "test-client-id";
    static final String CLIENT_SECRET = "test-client-secret";
    static final FakeGoogleServer google = new FakeGoogleServer(CLIENT_ID);

    /** Google 주소 중 서버↔Google 통신 3개만 가짜로 바꾼다. 브라우저가 가는 로그인 화면 주소는 진짜 Google 그대로 */
    @DynamicPropertySource
    static void useFakeGoogle(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.client.registration.google.client-id", () -> CLIENT_ID);
        registry.add("spring.security.oauth2.client.registration.google.client-secret", () -> CLIENT_SECRET);
        registry.add("spring.security.oauth2.client.provider.google.token-uri", () -> google.baseUrl() + "/token");
        registry.add("spring.security.oauth2.client.provider.google.jwk-set-uri", () -> google.baseUrl() + "/jwks");
        registry.add("spring.security.oauth2.client.provider.google.user-info-uri", () -> google.baseUrl() + "/userinfo");
        registry.add("app.admin-email", () -> "admin@gmail.com");
    }

    @AfterAll
    static void stopGoogle() {
        google.stop();
    }

    @Autowired
    TestRestTemplate rest;

    @Autowired
    UserRepository userRepository;

    @LocalServerPort
    int port;

    @Test
    void 구글_로그인_전체_흐름_Authorization_Code() {
        // 1) 로그인 전 → 401
        assertThat(get("/api/me", null).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        // 2) "Google로 로그인" 클릭 = GET /oauth2/authorization/google
        //    → 우리 서버가 Google 로그인 화면 주소로 302. 주소에 "누가, 무엇을, 어디로 돌려달라"가 적혀 있다
        ResponseEntity<String> start = get("/oauth2/authorization/google", null);
        assertThat(start.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String googleLoginUrl = start.getHeaders().getLocation().toString();
        assertThat(googleLoginUrl).startsWith("https://accounts.google.com/o/oauth2/v2/auth?");

        Map<String, String> params = queryParams(googleLoginUrl);
        assertThat(params)
                .containsEntry("response_type", "code")    // "토큰 말고 code를 달라" = Authorization Code 방식
                .containsEntry("client_id", CLIENT_ID)      // 우리 앱이 누구인지
                .containsEntry("scope", "openid profile email") // 무엇을 원하는지 (openid = 로그인)
                .containsEntry("redirect_uri", "http://localhost:" + port + "/login/oauth2/code/google") // 끝나면 어디로
                .containsKeys("state", "nonce");           // 위조 방지용 랜덤 값
        // ⭐ client-secret은 주소에 없다. 브라우저를 거치는 길(front channel)에는 비밀을 싣지 않는다
        assertThat(googleLoginUrl).doesNotContain(CLIENT_SECRET);

        // 우리 서버는 state를 세션에 기억해 둔다 → 그래서 쿠키가 생긴다
        String beforeLoginCookie = sessionCookie(start);
        assertThat(beforeLoginCookie).startsWith("JSESSIONID=");

        // 3) (브라우저가 Google 화면에서 로그인·동의했다고 치자)
        //    Google이 브라우저를 redirect_uri로 돌려보낸다: ?code=1회용코드&state=아까그값
        google.willLogin("google-uid-1", "user@gmail.com", "홍길동", params.get("nonce"));
        ResponseEntity<String> callback = get(callbackUri("fake-auth-code", rawParam(googleLoginUrl, "state")), beforeLoginCookie);

        //    우리 서버: state 확인 → code로 토큰 교환 → ID Token 검증 → 회원 연결 → 세션 저장 → "/"로 302
        assertThat(callback.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(callback.getHeaders().getLocation().getPath()).isEqualTo("/");
        String loginCookie = sessionCookie(callback);
        assertThat(loginCookie).isNotEqualTo(beforeLoginCookie); // 로그인 순간 세션 ID 교체 (세션 고정 방어, session-demo와 동일)

        // 4) ⭐ 3) 사이에 우리 서버 ↔ Google이 직접 통신했다 (back channel, 브라우저는 모름)
        FakeGoogleServer.TokenRequest tokenRequest = google.lastTokenRequest();
        assertThat(tokenRequest.body())
                .contains("grant_type=authorization_code")
                .contains("code=fake-auth-code");
        // client-secret은 여기서만 쓰인다 (HTTP Basic: base64("id:secret"))
        assertThat(tokenRequest.authorizationHeader())
                .isEqualTo("Basic " + base64(CLIENT_ID + ":" + CLIENT_SECRET));

        // 5) 이후는 session-demo와 같다: 쿠키로 요청 → 200
        ResponseEntity<String> me = get("/api/me", loginCookie);
        assertThat(me.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(me.getBody())
                .contains("user@gmail.com")
                .contains("ROLE_USER")
                .contains("google-uid-1")
                .contains(FakeGoogleServer.ISSUER);

        // 6) 자동 회원가입: 비밀번호 없이 (provider, sub)로 저장됐다
        User saved = userRepository.findByProviderAndProviderId("google", "google-uid-1").orElseThrow();
        assertThat(saved.getEmail()).isEqualTo("user@gmail.com");
        assertThat(saved.getRole()).isEqualTo(Role.USER);

        // 7) 권한은 우리 DB가 정한다 → USER는 관리자 API 403
        assertThat(get("/api/admin/hello", loginCookie).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // 8) 로그아웃 → 우리 세션 삭제 → 같은 쿠키로 401
        assertThat(post("/logout", loginCookie).getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(get("/api/me", loginCookie).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void state가_다르면_토큰_교환도_하지_않고_로그인_실패_CSRF_방어() {
        // 공격 시나리오: 공격자가 "자기 계정의 code"가 담긴 콜백 링크를 피해자에게 클릭시킨다
        // → 피해자가 공격자 계정으로 로그인돼서, 입력한 정보가 공격자에게 쌓인다
        // 방어: 콜백의 state가 "이 브라우저 세션이 보낸 state"와 같아야만 진행
        ResponseEntity<String> start = get("/oauth2/authorization/google", null);
        String cookie = sessionCookie(start);
        int tokenRequestsBefore = google.tokenRequestCount();

        ResponseEntity<String> callback = get(callbackUri("attacker-code", "attacker-state"), cookie);

        assertThat(callback.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(callback.getHeaders().getLocation().toString()).endsWith("/login?error");
        assertThat(google.tokenRequestCount()).isEqualTo(tokenRequestsBefore); // Google에 code를 보내지도 않음
        assertThat(get("/api/me", cookie).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void Google_키로_서명하지_않은_ID_Token은_거부된다() {
        // jwt-demo의 "변조 토큰 401"과 같은 원리. 차이: HS256 비밀키 대신 RS256 Google 공개키(/jwks)로 검증
        ResponseEntity<String> start = get("/oauth2/authorization/google", null);
        String location = start.getHeaders().getLocation().toString();
        google.willReturnForgedIdToken("google-uid-evil", "forged@gmail.com", "가짜", queryParams(location).get("nonce"));

        ResponseEntity<String> callback = get(callbackUri("fake-auth-code", rawParam(location, "state")), sessionCookie(start));

        assertThat(callback.getHeaders().getLocation().toString()).endsWith("/login?error");
        assertThat(userRepository.findByProviderAndProviderId("google", "google-uid-evil")).isEmpty();
    }

    @Test
    void 같은_sub로_다시_로그인하면_같은_회원이고_권한은_우리_DB_기준() {
        String first = loginWithGoogle("google-uid-admin", "admin@gmail.com", "관리자");
        assertThat(get("/api/admin/hello", first).getStatusCode()).isEqualTo(HttpStatus.OK); // app.admin-email → ADMIN

        // Google에서 이름을 바꾸고 다시 로그인 → 새 회원이 생기지 않고 기존 회원 프로필만 갱신
        loginWithGoogle("google-uid-admin", "admin@gmail.com", "관리자(이름변경)");

        List<User> admins = userRepository.findAll().stream()
                .filter(u -> u.getProviderId().equals("google-uid-admin")).toList();
        assertThat(admins).hasSize(1);
        assertThat(admins.get(0).getName()).isEqualTo("관리자(이름변경)");
    }

    // ---- 브라우저 흉내 ----

    /** 1번 테스트의 2)~3)을 한 번에: 로그인 시작 → Google 다녀온 척 → 로그인된 세션 쿠키 반환 */
    private String loginWithGoogle(String sub, String email, String name) {
        ResponseEntity<String> start = get("/oauth2/authorization/google", null);
        String location = start.getHeaders().getLocation().toString();
        google.willLogin(sub, email, name, queryParams(location).get("nonce"));
        ResponseEntity<String> callback = get(callbackUri("code-" + sub, rawParam(location, "state")), sessionCookie(start));
        assertThat(callback.getHeaders().getLocation().getPath()).isEqualTo("/");
        return sessionCookie(callback);
    }

    private URI callbackUri(String code, String rawState) {
        return URI.create("http://localhost:" + port + "/login/oauth2/code/google?code=" + code + "&state=" + rawState);
    }

    private ResponseEntity<String> get(String path, String cookie) {
        return get(URI.create("http://localhost:" + port + path), cookie);
    }

    private ResponseEntity<String> get(URI uri, String cookie) {
        return rest.exchange(uri, HttpMethod.GET, new HttpEntity<>(headers(cookie)), String.class);
    }

    private ResponseEntity<String> post(String path, String cookie) {
        return rest.exchange(URI.create("http://localhost:" + port + path), HttpMethod.POST, new HttpEntity<>(headers(cookie)), String.class);
    }

    private HttpHeaders headers(String cookie) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN, MediaType.TEXT_HTML));
        if (cookie != null) {
            headers.add(HttpHeaders.COOKIE, cookie);
        }
        return headers;
    }

    private static String sessionCookie(ResponseEntity<?> response) {
        String setCookie = response.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
        return setCookie == null ? null : setCookie.split(";")[0];
    }

    /** URL의 query를 디코딩해서 Map으로 */
    private static Map<String, String> queryParams(String url) {
        return Arrays.stream(URI.create(url).getRawQuery().split("&"))
                .map(pair -> pair.split("=", 2))
                .collect(Collectors.toMap(
                        kv -> kv[0],
                        kv -> URLDecoder.decode(kv[1], StandardCharsets.UTF_8)));
    }

    /** URL 인코딩된 그대로의 값 (콜백 URL에 다시 붙일 때 이중 인코딩을 피하려고) */
    private static String rawParam(String url, String name) {
        return Arrays.stream(URI.create(url).getRawQuery().split("&"))
                .filter(pair -> pair.startsWith(name + "="))
                .map(pair -> pair.substring(name.length() + 1))
                .findFirst().orElseThrow();
    }

    private static String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
