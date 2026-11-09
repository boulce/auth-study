package com.study.session.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, SecurityContextRepository securityContextRepository) throws Exception {
        http
                // ⚠️ 학습용으로 끔(curl 테스트 편의).
                // 세션 방식은 브라우저가 쿠키(JSESSIONID)를 "자동으로" 보내기 때문에 CSRF 공격에 취약하다.
                // → 실서비스 세션 방식에서는 반드시 켜야 한다. (JWT를 헤더로 보내는 방식과의 핵심 차이)
                .csrf(csrf -> csrf.disable())

                // 기본 로그인 폼/Basic 인증 대신, 우리가 만든 /api/auth/login API로 로그인한다.
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())

                // ⭐ 세션 방식의 핵심: 필요하면 서버가 세션을 만든다 (JWT 데모에서는 STATELESS로 바뀜)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))

                // ⭐ 요청마다 "세션에서" 로그인 정보(SecurityContext)를 꺼내오는 저장소
                .securityContext(context -> context
                        .securityContextRepository(securityContextRepository))

                // 인가 규칙: 위에서부터 순서대로 매칭
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/auth/signup", "/api/auth/login", "/error").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())

                .exceptionHandling(e -> e
                        // 인증 안 됨(누군지 모름) → 401
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                        // 인증은 됐지만 권한 없음 → 403
                        .accessDeniedHandler((request, response, ex) -> response.setStatus(HttpStatus.FORBIDDEN.value())))

                // ⭐ 로그아웃 = 서버에서 세션을 지운다 → 그 쿠키는 즉시 무용지물 (JWT는 이게 안 됨)
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK)));

        return http.build();
    }

    /** 로그인 성공 후 SecurityContext를 HttpSession에 저장하고, 다음 요청 때 꺼내오는 역할 */
    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /** UserDetailsService + PasswordEncoder를 조합해 "이메일/비밀번호가 맞는지" 판단하는 객체 */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
