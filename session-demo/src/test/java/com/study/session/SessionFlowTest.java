package com.study.session;

import com.study.session.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.*;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 실제 서버를 띄우고, 브라우저가 하는 일(쿠키 저장 → 매 요청에 Cookie 헤더 첨부)을 손으로 재현한다.
 * 이 테스트를 위에서부터 읽으면 세션 로그인의 전체 흐름이 된다.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SessionFlowTest {

    @Autowired
    TestRestTemplate rest;

    @Autowired
    UserRepository userRepository;

    @Test
    void 세션_로그인_전체_흐름() {
        // 1) 회원가입
        ResponseEntity<String> signup = post("/api/auth/signup", Map.of("email", "user@test.com", "password", "password123"), null);
        assertThat(signup.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        // 2) 로그인 안 하고 보호된 API 호출 → 401 (누군지 모름)
        assertThat(get("/api/me", null).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        // 3) 비밀번호 틀림 → 401
        ResponseEntity<String> wrong = post("/api/auth/login", Map.of("email", "user@test.com", "password", "wrong-password"), null);
        assertThat(wrong.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        // 4) 로그인 성공 → 서버가 세션을 만들고 Set-Cookie: JSESSIONID=...; HttpOnly 를 내려준다
        ResponseEntity<String> login = post("/api/auth/login", Map.of("email", "user@test.com", "password", "password123"), null);
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
        String setCookie = login.getHeaders().getFirst(HttpHeaders.SET_COOKIE);
        assertThat(setCookie).startsWith("JSESSIONID=").contains("HttpOnly");
        String sessionCookie = setCookie.split(";")[0]; // "JSESSIONID=ABC123..."

        // 5) 쿠키를 들고 요청 → 서버가 세션 저장소에서 사용자 정보를 찾아냄 → 200
        ResponseEntity<String> me = get("/api/me", sessionCookie);
        assertThat(me.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(me.getBody()).contains("user@test.com").contains("ROLE_USER");

        // 6) USER가 관리자 API 호출 → 403 (누군지는 알지만 권한 없음)
        assertThat(get("/api/admin/hello", sessionCookie).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // 7) ADMIN으로 로그인하면 관리자 API → 200
        ResponseEntity<String> adminLogin = post("/api/auth/login", Map.of("email", "admin@test.com", "password", "admin1234"), null);
        String adminCookie = adminLogin.getHeaders().getFirst(HttpHeaders.SET_COOKIE).split(";")[0];
        assertThat(get("/api/admin/hello", adminCookie).getStatusCode()).isEqualTo(HttpStatus.OK);

        // 8) ⭐ 로그아웃 → 서버가 세션을 삭제
        assertThat(post("/api/auth/logout", Map.of(), sessionCookie).getStatusCode()).isEqualTo(HttpStatus.OK);

        // 9) ⭐ 아까 그 쿠키를 그대로 다시 보내도 → 401. 서버에 세션이 없으니 "즉시 무효화"된다.
        //    (JWT는 서버가 아무것도 저장하지 않아서, 이 단계가 기본적으로 불가능하다)
        assertThat(get("/api/me", sessionCookie).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void 비밀번호는_BCrypt_해시로_저장된다() {
        post("/api/auth/signup", Map.of("email", "hash@test.com", "password", "password123"), null);

        String stored = userRepository.findByEmail("hash@test.com").orElseThrow().getPassword();
        assertThat(stored).isNotEqualTo("password123").startsWith("$2a$");
    }

    @Test
    void 로그인_전에_있던_세션ID는_로그인하면_바뀐다_세션고정공격_방어() {
        post("/api/auth/signup", Map.of("email", "fixation@test.com", "password", "password123"), null);

        // 첫 로그인으로 세션 A를 받은 상태에서, 그 쿠키를 들고 다시 로그인
        String cookieA = post("/api/auth/login", Map.of("email", "fixation@test.com", "password", "password123"), null)
                .getHeaders().getFirst(HttpHeaders.SET_COOKIE).split(";")[0];
        String cookieB = post("/api/auth/login", Map.of("email", "fixation@test.com", "password", "password123"), cookieA)
                .getHeaders().getFirst(HttpHeaders.SET_COOKIE).split(";")[0];

        assertThat(cookieB).isNotEqualTo(cookieA);
        // 예전 세션 ID는 더 이상 통하지 않는다
        assertThat(get("/api/me", cookieA).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(get("/api/me", cookieB).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    // ---- 브라우저 흉내: 쿠키가 있으면 Cookie 헤더에 붙여서 보낸다 ----

    private ResponseEntity<String> post(String url, Map<String, String> body, String cookie) {
        return rest.exchange(url, HttpMethod.POST, new HttpEntity<>(body, headers(cookie)), String.class);
    }

    private ResponseEntity<String> get(String url, String cookie) {
        return rest.exchange(url, HttpMethod.GET, new HttpEntity<>(headers(cookie)), String.class);
    }

    private HttpHeaders headers(String cookie) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN));
        if (cookie != null) {
            headers.add(HttpHeaders.COOKIE, cookie);
        }
        return headers;
    }
}
