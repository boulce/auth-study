# oauth2-demo — Google 로그인 (OAuth2 Authorization Code + OIDC)

> 한 줄 요약: **비밀번호 확인을 Google에게 맡기고**, Google이 서명해 준 **ID Token(JWT)** 으로 "이 사람이 누구인지"를 받는다. 그다음은 session-demo처럼 우리 세션으로 로그인 상태를 유지한다.

## 0. 용어 4개만

| 용어 | 이 데모에서 | 뜻 |
|---|---|---|
| Resource Owner | 사용자 | Google 계정 주인 |
| Client | **우리 서버** (oauth2-demo) | Google에게 "이 사람 누군지 알려줘"라고 부탁하는 앱 |
| Authorization Server | Google (accounts.google.com) | 로그인·동의 화면을 띄우고 토큰을 발급 |
| Resource Server | Google API (userinfo 등) | Access Token을 받고 데이터를 준다 |

- **OAuth2** = 원래는 "권한 위임" 규약 (예: 이 앱이 내 Google 캘린더를 읽어도 된다). 로그인용이 아니다.
- **OIDC (OpenID Connect)** = OAuth2 위에 "로그인"을 얹은 규약. scope에 `openid`를 넣으면 **ID Token**이 추가로 온다.
- "Google 로그인" = 정확히는 **OIDC**. 이 데모의 `scope: openid, profile, email`.

## 1. 전체 흐름 (Authorization Code)

```
 브라우저                         우리 서버 (Client)                         Google
    │  ① "Google로 로그인" 클릭         │                                        │
    │ ─ GET /oauth2/authorization/google ─▶                                     │
    │                                   │ state, nonce 생성 → 세션에 기억         │
    │ ◀─ 302 accounts.google.com/...?response_type=code&client_id&scope         │
    │        &redirect_uri&state&nonce  (client-secret은 없다!)                  │
    │                                                                            │
    │ ─────────────── ② Google 로그인 화면, 비밀번호 입력, 동의 ─────────────────▶ │
    │ ◀────────────── 302 우리서버/login/oauth2/code/google?code=1회용&state ───── │
    │                                                                            │
    │ ─ ③ GET /login/oauth2/code/google?code&state (+ JSESSIONID) ─▶             │
    │                                   │ ④ state == 세션에 기억한 값? (CSRF 방어) │
    │                                   │ ⑤ POST /token  code + client-secret ──▶ │  ← back channel
    │                                   │ ◀── access_token, id_token(JWT) ─────── │    (브라우저 모름)
    │                                   │ ⑥ ID Token 검증: Google 공개키(JWKS)로   │
    │                                   │    RS256 서명 + iss, aud, exp, nonce     │
    │                                   │ ⑦ GET /userinfo (Bearer access) ──────▶ │
    │                                   │ ⑧ sub로 우리 회원 찾기/자동가입, 권한 부여 │
    │                                   │ ⑨ 세션 저장 (세션 ID 교체)               │
    │ ◀─ 302 / + Set-Cookie: JSESSIONID │                                        │
    │                                                                            │
    │ ─ GET /api/me (Cookie) ─▶ 이후는 session-demo와 완전히 같다                 │
```

**왜 토큰을 바로 안 주고 code를 먼저 주나?**
- ②의 302는 **브라우저를 거친다(front channel)**. 주소창·히스토리·로그에 남을 수 있다.
- 그래서 여기엔 **1회용·짧은 수명의 code**만 싣는다. code만 훔쳐서는 소용없다. 토큰으로 바꾸려면 **client-secret**이 필요하기 때문이다.
- 진짜 토큰은 ⑤ **우리 서버 ↔ Google 직통(back channel)** 으로만 받는다.

## 2. 읽는 순서 (약 40분)

| 순서 | 파일 | 볼 포인트 |
|---|---|---|
| 1 | `src/test/.../OAuth2FlowTest.java` | **먼저 읽기.** 1번 테스트 1)~8)이 위 그림 ①~⑨ |
| 2 | `src/test/.../FakeGoogleServer.java` | Google이 우리 서버에게 해주는 3가지(token, jwks, userinfo). ID Token을 어떻게 만드는지 |
| 3 | `config/SecurityConfig.java` | `oauth2Login()` 한 블록이 흐름 전체. 자동으로 생기는 URL 2개 |
| 4 | `auth/GoogleOidcUserService.java` | ⭐ 우리가 직접 짠 거의 유일한 로직: sub로 회원 연결, 권한은 우리 DB |
| 5 | `user/User.java` | password 컬럼이 없다. `(provider, providerId)`로 식별 |
| 6 | `application.yml` | client-id, client-secret, scope. Google 주소들은 Spring이 이미 앎 |

## 3. 실행

### 테스트 (Google 계정 없이 가능)
```bash
./gradlew test    # 4개 PASSED
```
테스트는 `FakeGoogleServer`가 Google의 토큰·공개키·프로필 엔드포인트를 대신한다. 브라우저가 가는 로그인 화면 주소만 진짜 Google 그대로다.

### 진짜 Google로 (선택, 약 10분)
1. https://console.cloud.google.com → 프로젝트 만들기
2. **Google 인증 플랫폼(OAuth 동의 화면)** 설정: 사용자 유형 "외부", 앱 이름·이메일 입력, **테스트 사용자에 내 Gmail 추가**
3. **클라이언트(사용자 인증 정보) → OAuth 클라이언트 ID 만들기** → 유형 "웹 애플리케이션"
   - 승인된 리디렉션 URI: `http://localhost:8080/login/oauth2/code/google` (한 글자라도 다르면 `redirect_uri_mismatch`)
4. 발급된 클라이언트 ID / 보안 비밀을 환경변수로 (파일에 쓰지 말 것)
```bash
export GOOGLE_CLIENT_ID='xxxx.apps.googleusercontent.com'
export GOOGLE_CLIENT_SECRET='GOCSPX-...'
export ADMIN_EMAIL='내gmail@gmail.com'   # 선택: 이 계정은 ADMIN
./gradlew bootRun
```
5. 브라우저로 http://localhost:8080 → "Google로 로그인" → `/api/me`에서 내 sub, 이메일 확인

(콘솔 메뉴 이름은 Google이 자주 바꾼다. 위 이름과 다르면 "OAuth client ID"로 찾으면 된다.)

## 4. 이 코드로 답할 수 있어야 하는 면접 질문

1. **OAuth2와 OIDC 차이?** → OAuth2는 권한 위임(인가), OIDC는 그 위의 로그인(인증) 규약. OIDC는 ID Token(JWT)을 추가로 준다
2. **Authorization Code 흐름을 설명해 보세요** → 1장 그림 ①~⑨
3. **왜 code를 거쳐서 토큰을 받나?** → 브라우저 경유 구간(front channel)에 토큰을 노출하지 않으려고. code는 1회용이고, 교환엔 client-secret이 필요(back channel)
4. **state는 왜 필요?** → CSRF. 공격자가 자기 code가 든 콜백 링크로 피해자를 공격자 계정에 로그인시키는 것을 막음 (테스트 2: 토큰 교환조차 안 함)
5. **nonce는?** → ID Token 재전송(replay) 방지. 우리가 보낸 nonce가 ID Token 안에 그대로 있어야 함
6. **ID Token은 어떻게 검증?** → jwt-demo `verify()`와 같은 순서. 차이: HS256 비밀키 대신 **RS256 + Google 공개키(JWKS)**. 그리고 `iss`=Google, `aud`=우리 client-id(다른 앱용 토큰 거부), `exp`, `nonce` (테스트 3)
7. **왜 RS256(공개키)?** → Google은 수많은 앱에 토큰을 준다. 비밀키를 나눠줄 수 없으니 개인키로 서명하고 공개키를 공개 → 누구나 검증 가능, 아무도 위조 불가
8. **소셜 회원은 무엇으로 식별?** → `sub`(provider 내 고유 ID). 이메일은 바뀔 수 있다. `(provider, sub)` 유니크
9. **권한은 누가 정하나?** → 인증(누구인지)은 Google, 인가(무엇을 할 수 있나)는 우리 DB (테스트 4)
10. **로그아웃하면 Google에서도 로그아웃되나?** → 아니다. 우리 세션만 지운다
11. **SPA·모바일 앱이면?** → client-secret을 숨길 수 없다 → **PKCE**(code_verifier/challenge)로 code 탈취를 막는다

## 5. 실무 변형: Google 로그인 + 우리 JWT 발급

이 데모는 로그인 후 **세션**(session-demo 방식)이다. 프론트가 분리된 SPA·모바일이면 로그인 성공 순간에 **jwt-demo의 토큰을 발급**하는 구성을 많이 쓴다.

```java
.oauth2Login(oauth2 -> oauth2
        .userInfoEndpoint(u -> u.oidcUserService(googleOidcUserService))
        .successHandler((request, response, authentication) -> {
            TokenResponse tokens = tokenService.issue(authentication.getName()); // jwt-demo의 TokenService
            // 토큰을 URL에 싣지 않는다(front channel). HttpOnly 쿠키로 주거나, 1회용 코드를 주고 프론트가 API로 교환
            ...
        }))
.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 단, 로그인 진행 중 state 보관은 별도 저장소 필요
```

## 6. 세 프로젝트 비교

| | session-demo | jwt-demo | oauth2-demo |
|---|---|---|---|
| 비밀번호 확인 | 우리 서버 (BCrypt) | 우리 서버 (BCrypt) | **Google** |
| DB에 password | 있음 | 있음 | **없음** |
| "누구인지" 증명 | 세션 ID | 우리가 서명한 JWT (HS256) | Google이 서명한 ID Token (RS256) → 이후 세션 |
| 서명 검증 키 | — | 우리 비밀키 | Google 공개키 (JWKS) |
| 로그인 후 상태 유지 | 세션 | 토큰 (STATELESS) | 세션 (JWT로 바꿀 수 있음, 5장) |
| 우리가 짠 핵심 코드 | `AuthController.login()` | `JwtProvider`, `JwtAuthenticationFilter` | `GoogleOidcUserService` |
