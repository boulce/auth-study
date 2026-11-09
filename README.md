# auth-study

세션 · JWT · OAuth2 인증을 **짧은 시간에 비교하며 이해**하기 위한 미니 프로젝트 모음.

| 프로젝트 | 핵심 질문 | 상태 |
|---|---|---|
| [session-demo](./session-demo) | 서버가 로그인 상태를 **저장**하면 어떻게 동작하나? | ✅ |
| jwt-demo | 서버가 아무것도 저장하지 않으면 어떻게 "누구인지" 아나? | 예정 |
| oauth2-demo | 비밀번호를 우리가 받지 않고 Google에게 맡기면? | 예정 |

공통 API 모양을 맞춰서, 같은 요청이 방식별로 어떻게 다르게 처리되는지 비교할 수 있게 했다.

- Spring Boot 3.3 / Spring Security 6 / Java 17 / H2(in-memory)
- 각 프로젝트: `./gradlew test` 로 흐름 검증, `./gradlew bootRun` 으로 실행
