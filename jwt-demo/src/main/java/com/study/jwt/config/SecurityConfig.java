package com.study.jwt.config;

import com.study.jwt.jwt.JwtAuthenticationFilter;
import com.study.jwt.jwt.JwtProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtProvider jwtProvider) throws Exception {
        http
                // 토큰을 쿠키가 아니라 Authorization 헤더로 보낸다 → 브라우저가 자동으로 붙이지 않음 → CSRF 위험이 낮아 끈다
                // (단, 토큰을 쿠키에 넣는 방식이면 CSRF를 다시 신경 써야 한다)
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .logout(logout -> logout.disable()) // 로그아웃은 AuthController에서 직접 (Refresh 삭제)

                // ⭐ STATELESS: 세션을 만들지도, 읽지도 않는다. JSESSIONID 쿠키가 생기지 않는다.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // ⭐ 우리 필터를 로그인 처리 필터 앞에 끼운다 → 매 요청마다 토큰 검증
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)

                // 인가 규칙은 session-demo와 완전히 같다 (인증 방식이 달라도 인가는 그대로)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/signup", "/api/auth/login", "/api/auth/refresh", "/error").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )

                .exceptionHandling(e -> e
                        // 401: 토큰이 없거나, 필터에서 검증 실패. 학습용으로 사유를 body에 보여준다.
                        // (클라이언트는 "만료된 토큰"을 보고 /refresh를 호출하면 된다)
                        .authenticationEntryPoint((request, response, ex) -> {
                            Object reason = request.getAttribute(JwtAuthenticationFilter.ERROR_ATTRIBUTE);
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
                            response.setContentType("text/plain;charset=UTF-8");
                            response.getWriter().write(reason != null ? "토큰 거부: " + reason : "토큰 없음");
                        })
                        // 403: 토큰은 유효(누군지 앎)한데 권한 부족
                        .accessDeniedHandler((request, response, ex) -> response.setStatus(HttpStatus.FORBIDDEN.value()))
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
