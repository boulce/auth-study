package com.study.jwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * ⭐ 매 요청마다 실행. session-demo에서 "세션 저장소 조회"가 하던 일을 여기서 "토큰 서명 검증"으로 한다.
 *
 * Authorization: Bearer eyJ... → JwtProvider.verify() → SecurityContext에 사용자 넣기 → 다음 필터 → (인가 검사) → Controller
 *
 * @Component를 붙이지 않는다. 붙이면 Spring Boot가 일반 서블릿 필터로도 등록해서 두 번 실행된다.
 * (SecurityConfig에서 new로 만들어 SecurityFilterChain에만 넣음)
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    /** 거부 사유를 401 응답(SecurityConfig의 entryPoint)까지 전달하기 위한 request attribute 이름 */
    public static final String ERROR_ATTRIBUTE = "jwt.error";

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtProvider jwtProvider;

    public JwtAuthenticationFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (header != null && header.startsWith(BEARER_PREFIX)) {
            try {
                JwtClaims claims = jwtProvider.verify(header.substring(BEARER_PREFIX.length()));
                if (claims.type() != TokenType.ACCESS) {
                    throw new InvalidTokenException("Refresh Token으로는 API를 호출할 수 없음");
                }

                // ⭐ DB 조회 없음. 토큰 안의 sub, role을 그대로 믿는다 (서명이 맞았으니까)
                //    → 빠르고 서버가 상태를 안 가짐. 대신 DB에서 권한을 바꿔도 토큰 만료 전까지는 예전 권한.
                UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                        claims.email(), null, List.of(new SimpleGrantedAuthority("ROLE_" + claims.role().name())));
                authentication.setDetails(claims);

                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);
                // session-demo와 달리 saveContext()가 없다. 이 요청이 끝나면 SecurityContext는 사라진다 (STATELESS)
            } catch (InvalidTokenException e) {
                // 여기서 바로 401을 쓰지 않고 "인증 안 된 상태"로 넘긴다.
                // → permitAll 경로(/login 등)는 만료 토큰이 붙어 와도 통과, 보호된 경로는 entryPoint가 401
                SecurityContextHolder.clearContext();
                request.setAttribute(ERROR_ATTRIBUTE, e.getMessage());
            }
        }

        filterChain.doFilter(request, response);
    }
}
