package com.study.oauth2.config;

import com.study.oauth2.auth.GoogleOidcUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, GoogleOidcUserService googleOidcUserService) throws Exception {
        http
                // 학습용으로 끈다 (로그아웃 버튼을 단순 form으로 보내려고). 로그인 후 세션 방식이라 실서비스에서는 켜야 한다.
                // 참고: OAuth2 로그인 콜백 자체의 CSRF는 state 파라미터가 막는다
                .csrf(csrf -> csrf.disable())

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/error").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )

                // ⭐ 이 한 블록이 OAuth2 로그인 전체. 아래 두 URL이 자동으로 생긴다:
                //   GET /oauth2/authorization/google   → Google 로그인 페이지로 302 (client_id, scope, state, nonce, redirect_uri 붙여서)
                //   GET /login/oauth2/code/google?code=..&state=..  → Google이 돌려보내는 곳(콜백). state 확인 → code로 토큰 교환 → ID Token 검증
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo.oidcUserService(googleOidcUserService))
                        .defaultSuccessUrl("/", true)
                )
                // 로그인 이후는 session-demo와 같다: 세션에 저장, JSESSIONID 쿠키 (README 5장: JWT로 바꾸는 방법)

                .exceptionHandling(e -> e
                        // /api/** 는 로그인 페이지로 리다이렉트하지 말고 401 (그 외 경로는 Google 로그인으로 리다이렉트)
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                request -> request.getRequestURI().startsWith("/api/"))
                        .accessDeniedHandler((request, response, ex) -> response.setStatus(HttpStatus.FORBIDDEN.value()))
                )

                // 우리 서비스 세션만 지운다. Google 로그인 상태는 그대로 (Google에서도 로그아웃되는 게 아님)
                .logout(logout -> logout.logoutUrl("/logout").logoutSuccessUrl("/"));

        return http.build();
    }
}
