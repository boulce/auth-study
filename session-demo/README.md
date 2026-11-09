# session-demo — 세션 기반 로그인

> 한 줄 요약: **서버가 "세션 ID ↔ 로그인 정보"를 저장**하고, 브라우저는 **세션 ID만 쿠키(JSESSIONID)로** 들고 다닌다.

## 1. 전체 흐름

```
[로그인]
Client ── POST /api/auth/login {email, pw} ──▶ Server
                                               ① DB에서 email 조회 (CustomUserDetailsService)
                                               ② BCrypt.matches(입력 pw, DB 해시)
                                               ③ 세션 생성: 서버 메모리에 { "A1B2..." : 로그인정보 } 저장
Client ◀── 200 + Set-Cookie: JSESSIONID=A1B2...; HttpOnly ──

[이후 모든 요청]
Client ── GET /api/me  (Cookie: JSESSIONID=A1B2...) ──▶ Server
          ↑ 브라우저가 자동으로 붙여 보냄                  ④ 세션 저장소에서 "A1B2..." 조회 → 로그인정보 꺼냄
                                                         ⑤ SecurityContext에 넣음 → 인가(권한) 검사 → Controller
Client ◀── 200 {email, roles} ──

[로그아웃]
Client ── POST /api/auth/logout (Cookie) ──▶ Server: 세션 "A1B2..." 삭제
→ 같은 쿠키로 다시 요청해도 401 (서버에 없으니까) = 즉시 무효화 ✅
```

## 2. 읽는 순서 (약 30분)

| 순서 | 파일 | 볼 포인트 |
|---|---|---|
| 1 | `src/test/.../SessionFlowTest.java` | **먼저 읽기.** 1)~9) 주석이 곧 전체 시나리오 |
| 2 | `config/SecurityConfig.java` | ⭐ 표시: `IF_REQUIRED`, `HttpSessionSecurityContextRepository`, `logout().invalidateHttpSession` |
| 3 | `auth/AuthController.java` | `login()`의 ①~④ — 특히 ④ `saveContext()` 한 줄이 "세션에 저장"하는 순간 |
| 4 | `user/CustomUserDetailsService.java` | 로그인 시 DB 조회가 일어나는 곳, `roles()` → `ROLE_` 접두사 |
| 5 | `api/DemoController.java` | `/api/me` 응답에 sessionId가 보임 = 서버에 세션이 진짜 있다 |
| 6 | `application.yml` | 세션 timeout, `http-only` |

## 3. 직접 실행해 보기 (선택)

```bash
./gradlew bootRun

# 회원가입
curl -i -X POST localhost:8080/api/auth/signup -H 'Content-Type: application/json' \
  -d '{"email":"user@test.com","password":"password123"}'

# 로그인 → 응답 헤더의 Set-Cookie: JSESSIONID 확인 (-c: 쿠키를 파일에 저장 = 브라우저 역할)
curl -i -c cookie.txt -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"user@test.com","password":"password123"}'

curl -i -b cookie.txt localhost:8080/api/me             # 200 (-b: 저장된 쿠키를 보냄)
curl -i -b cookie.txt localhost:8080/api/admin/hello    # 403 (USER라서)
curl -i               localhost:8080/api/me             # 401 (쿠키 없음)

curl -i -b cookie.txt -X POST localhost:8080/api/auth/logout   # 200, 서버 세션 삭제
curl -i -b cookie.txt localhost:8080/api/me             # 401 ← 같은 쿠키인데 막힘!
```
관리자 계정: `admin@test.com / admin1234` (앱 시작 시 자동 생성)

## 4. 이 코드로 답할 수 있어야 하는 면접 질문

1. **세션 방식은 서버가 무엇을 저장하고, 클라이언트는 무엇을 들고 있나요?**
   → 서버: 세션 ID ↔ 사용자 정보 / 클라이언트: 세션 ID만(쿠키)
2. **세션의 장점은?** → 서버에서 지우면 **즉시 무효화**(강제 로그아웃, 탈취 대응 쉬움)
3. **서버가 여러 대면 무슨 문제가?**
   → 이 데모는 세션이 **서버(Tomcat) 메모리**에 있다. 서버 2대면 A에서 로그인 후 B로 가면 401.
   → 해결: Sticky Session / 세션 클러스터링 / **Redis 같은 공용 세션 저장소**(Spring Session)
4. **HttpOnly는 왜?** → JS가 쿠키를 못 읽게 → XSS로 세션 ID 탈취 방지
5. **세션 고정 공격이란? 어떻게 막나?** → 공격자가 심어둔 세션 ID로 피해자가 로그인 → 로그인 시 세션 ID 교체 (`changeSessionId()`, 테스트로 검증)
6. **세션 방식에서 CSRF를 신경 써야 하는 이유?** → 브라우저가 쿠키를 **자동으로** 보내서, 다른 사이트에서 유도한 요청에도 로그인 상태가 실림
   (이 데모는 학습 편의로 껐다 — `SecurityConfig` 주석 참고)
7. **비밀번호는 어떻게 비교하나?** → DB엔 BCrypt 해시(salt 포함). 입력값을 같은 salt로 해시해 비교. 복호화 X

## 5. 다음(jwt-demo)에서 바뀌는 것 미리보기

| | session-demo | jwt-demo |
|---|---|---|
| 세션 정책 | `IF_REQUIRED` (세션 생성) | `STATELESS` (세션 안 만듦) |
| 로그인 응답 | `Set-Cookie: JSESSIONID` | Body에 Access/Refresh Token |
| 요청 시 보내는 것 | Cookie (자동) | `Authorization: Bearer ...` (직접) |
| 서버가 "누구인지" 아는 법 | 세션 저장소 **조회** | 토큰 서명 **계산·검증** |
| 로그아웃 즉시 무효화 | ✅ 세션 삭제 | ❌ 기본 불가 → Refresh 삭제·짧은 만료로 보완 |
| 서버 여러 대 | 세션 공유 필요 | 키만 공유하면 OK |
