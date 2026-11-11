# jwt-demo — JWT 기반 로그인 (Access + Refresh)

> 한 줄 요약: **서버는 아무것도 저장하지 않고**, 로그인 정보를 **서명한 토큰**으로 클라이언트에게 준다. 매 요청마다 서버는 **서명만 다시 계산해서** 진짜인지 확인한다.

session-demo와 API 모양·회원가입·`user/` 패키지·인가 규칙이 **완전히 같다.** 바뀐 곳만 보면 된다.

## 1. 전체 흐름

```
[로그인]
Client ── POST /api/auth/login {email, pw} ──▶ Server
                                               ① DB 조회 + BCrypt 비교 (session-demo와 동일)
                                               ② Access Token(15분), Refresh Token(14일) 발급
                                               ③ Refresh만 DB에 저장. Access는 어디에도 저장 안 함
Client ◀── 200 {accessToken, refreshToken}  (Set-Cookie 없음)
          클라이언트가 직접 보관

[이후 모든 요청]
Client ── GET /api/me  (Authorization: Bearer eyJ...) ──▶ JwtAuthenticationFilter
          ↑ 클라이언트가 직접 붙여 보냄                     ④ verify(): 모양 → alg → ⭐서명 → 만료
                                                           ⑤ payload의 sub, role로 SecurityContext 채움 (DB 조회 X)
                                                           ⑥ 인가(권한) 검사 → Controller
Client ◀── 200 {email, roles}

[Access 만료]
Client ── GET /api/me (만료 토큰) ──▶ 401 "토큰 거부: 만료된 토큰"
Client ── POST /api/auth/refresh {refreshToken} ──▶ ⑦ 서명·만료 검증 + ⭐DB에 있는지 확인
Client ◀── 200 {새 accessToken, 새 refreshToken}       ⑧ Rotation: DB의 Refresh를 새 것으로 교체

[로그아웃]
Client ── POST /api/auth/logout (Bearer access) ──▶ DB의 Refresh 삭제
→ 재발급은 막힘 ✅ / 그러나 이미 가진 Access는 15분 동안 계속 통과 ❌ (JWT의 한계)
```

### 서명 검증이 "위조 불가"인 이유 (가장 중요)

```
토큰:  eyJhbGciOi... . eyJzdWIiOi... . X9fK2a...
       └─ header ─┘   └─ payload ─┘   └ 서명 ┘

서버:  HMAC-SHA256(비밀키, "header.payload")  ──▶  계산한 서명
       계산한 서명 == 토큰의 서명 ?  → 같으면 통과, 다르면 401
```
- payload를 `"role":"USER"` → `"ADMIN"`으로 바꾸면 → 서버가 다시 계산한 서명이 달라짐 → 401
- 맞는 서명을 새로 만들려면 비밀키가 필요한데, 비밀키는 서버만 안다
- **"디코딩해서 확인"이 아니다.** 디코딩은 누구나 할 수 있다(암호화 X). 검증의 핵심은 **서명 재계산**

## 2. 읽는 순서 (약 40분)

| 순서 | 파일 | 볼 포인트 |
|---|---|---|
| 1 | `src/test/.../JwtFlowTest.java` | **먼저 읽기.** 1번=전체 흐름, 2~5번=공격·만료, 6~7번=Refresh와 한계 |
| 2 | `jwt/JwtProvider.java` | ⭐⭐ 핵심. `createToken()` 발급, `verify()` ①~⑤ 검증 순서 |
| 3 | `jwt/JwtAuthenticationFilter.java` | session-demo의 "세션 조회" 자리에 들어간 것. DB 조회가 없다 |
| 4 | `config/SecurityConfig.java` | `STATELESS`, `addFilterBefore`, 401 사유 출력 |
| 5 | `auth/AuthController.java` | `login()` ②: `saveContext()` 대신 토큰을 body로 |
| 6 | `auth/TokenService.java` | `refresh()` ①~④: 재사용 감지, Rotation, `noRollbackFor` |
| 7 | `auth/RefreshToken.java` | 왜 Refresh만 저장하나, 실무와 다른 점 |
| 8 | `application.yml` | 비밀키, 만료 시간 |

session-demo와 나란히 비교하고 싶으면:
```bash
diff session-demo/src/main/java/com/study/session/config/SecurityConfig.java \
     jwt-demo/src/main/java/com/study/jwt/config/SecurityConfig.java
```

## 3. 직접 실행해 보기 (선택)

```bash
./gradlew test       # 7개 테스트 PASSED 확인
./gradlew bootRun    # 8080 (session-demo가 켜져 있으면 먼저 끄기)

B=localhost:8080
curl -i -X POST $B/api/auth/signup -H 'Content-Type: application/json' \
  -d '{"email":"user@test.com","password":"password123"}'

# 로그인 → 응답 body에 토큰. 헤더에 Set-Cookie가 없는 것도 확인
curl -i -X POST $B/api/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"user@test.com","password":"password123"}'

# 위 응답의 accessToken, refreshToken 값을 복사해서 변수에
ACCESS='eyJ...'
REFRESH='eyJ...'

# payload를 비밀키 없이 읽어보기 (= 암호화가 아님). https://jwt.io 에 붙여넣어도 보인다
echo $ACCESS | cut -d. -f2 | base64 -d 2>/dev/null; echo

curl -i $B/api/me          -H "Authorization: Bearer $ACCESS"     # 200
curl -i $B/api/admin/hello -H "Authorization: Bearer $ACCESS"     # 403 (USER)
curl -i $B/api/me                                                 # 401 토큰 없음
curl -i $B/api/me          -H "Authorization: Bearer ${ACCESS}x"  # 401 서명 불일치
curl -i $B/api/me          -H "Authorization: Bearer $REFRESH"    # 401 Refresh로는 API 불가

curl -i -X POST $B/api/auth/refresh -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}"   # 200 새 토큰 2개
curl -i -X POST $B/api/auth/refresh -H 'Content-Type: application/json' \
  -d "{\"refreshToken\":\"$REFRESH\"}"   # 401 같은 Refresh 재사용 감지
```
관리자 계정: `admin@test.com / admin1234` (앱 시작 시 자동 생성)

(`base64 -d`는 패딩이 없어서 끝이 조금 잘릴 수 있다. 내용 확인용으로는 충분)

## 4. 이 코드로 답할 수 있어야 하는 면접 질문

1. **JWT가 뭔가요?** → 사용자 정보(claim)를 담고 **서버 비밀키로 서명한 토큰**. `header.payload.signature`, Base64URL 인코딩
2. **서버는 JWT를 어떻게 검증하나요?** (2차 AI면접 약점)
   → ① 3부분 형식 확인 → ② alg가 서버가 허용한 것(HS256)인지 → ③ **비밀키로 header.payload를 다시 서명해 토큰의 서명과 비교** → ④ exp 확인 → ⑤ sub·role로 SecurityContext 채움 → 인가 검사
   → `JwtProvider.verify()` 그 자체
3. **JWT는 암호화인가요?** → 아니다. 인코딩 + 서명. 누구나 읽을 수 있고, **못 바꿀 뿐**이다 → 민감정보 금지 (테스트 2)
4. **JWT 보안 문제와 방지책?**
   - 탈취 → Access 만료 짧게, HTTPS, 저장 위치(XSS 대비 HttpOnly 쿠키 고려)
   - 변조 → 서명 검증 (테스트 3)
   - alg:none → 서버가 알고리즘 고정 (테스트 4)
   - 비밀키 유출 → 환경변수·Secret Manager, 충분한 길이(256비트 이상), 키 교체
   - Refresh 탈취 → DB 저장 + Rotation + 재사용 감지 (테스트 6)
5. **로그아웃은 어떻게?** → Refresh 삭제. Access는 못 지운다(서버에 없으니까) → 짧은 만료로 감수하거나, 즉시 막아야 하면 jti 블랙리스트(Redis) (테스트 7)
6. **Refresh Token은 왜 따로 두고, 왜 서버에 저장하나?** → Access를 짧게 하면서도 매번 재로그인 안 하게. 수명이 길어서 위험하니 서버에 두고 폐기 가능하게
7. **세션 대비 장단점?** → 장점: 서버가 상태 없음 → 서버 여러 대여도 **비밀키만 공유**하면 됨, 매 요청 DB 조회 없음 / 단점: 즉시 무효화 어려움, 토큰이 커서 매 요청 전송량 증가, 권한 변경이 만료 전까지 반영 안 됨
8. **HS256 vs RS256?** → HS256: 같은 비밀키로 서명·검증 (서버 하나가 다 할 때). RS256: 개인키로 서명, **공개키로 검증** → 발급 서버와 검증 서버가 다를 때(MSA, 그리고 다음 oauth2-demo의 Google ID Token이 RS256)

## 5. session-demo와 한눈에 비교

| | session-demo | jwt-demo |
|---|---|---|
| 세션 정책 | `IF_REQUIRED` | `STATELESS` |
| 로그인 후 서버가 하는 일 | `saveContext()` → 세션 저장 | 토큰 생성 → body로 응답 |
| 로그인 응답 | `Set-Cookie: JSESSIONID` | `{accessToken, refreshToken}` |
| 요청 시 보내는 것 | Cookie (브라우저가 자동) | `Authorization: Bearer` (클라이언트가 직접) |
| 서버가 "누구인지" 아는 법 | 세션 저장소 **조회** | `JwtAuthenticationFilter`에서 서명 **계산·비교** |
| 서버가 저장하는 것 | 세션 전체 | Refresh Token만 |
| 로그아웃 후 같은 인증정보 | 401 ✅ 즉시 무효 | Access는 200 ❌ (만료까지) |
| CSRF | 신경 써야 함 (쿠키 자동 전송) | 헤더 방식이면 위험 낮음 |
| 서버 여러 대 | 세션 공유(Redis 등) 필요 | 비밀키만 공유 |

## 6. 실무에서는 (라이브러리 사용)

이 데모는 원리를 보이려고 `JwtProvider`를 직접 구현했다. 실무에서는 검증된 라이브러리를 쓴다. 하는 일은 같다.

```java
// jjwt 0.12 예시
SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(UTF_8));

String token = Jwts.builder().subject(email).claim("role", "USER")
        .issuedAt(now).expiration(exp).signWith(key).compact();

Claims claims = Jwts.parser().verifyWith(key).build()   // alg 고정 + 서명 검증 + exp 검증
        .parseSignedClaims(token).getPayload();         // 실패 시 JwtException
```
Spring Security에는 `oauth2-resource-server`(+ nimbus)로 Bearer 검증 필터를 설정만으로 붙이는 방법도 있다.
