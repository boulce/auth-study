package com.study.jwt.api;

import com.study.jwt.jwt.JwtClaims;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class DemoController {

    /**
     * session-demo의 /api/me와 같은 API.
     * 차이: Authentication은 세션이 아니라 JwtAuthenticationFilter가 "토큰에서 꺼내" 만든 것. sessionId는 없다.
     */
    @GetMapping("/me")
    public Map<String, Object> me(Authentication authentication) {
        JwtClaims claims = (JwtClaims) authentication.getDetails();
        return Map.of(
                "email", authentication.getName(),
                "roles", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList(),
                "tokenIssuedAt", claims.issuedAt().toString(),
                "tokenExpiresAt", claims.expiresAt().toString(),
                "howServerKnowsYou", "세션·DB 조회 없이 토큰 서명 검증만으로 확인"
        );
    }

    /** ADMIN만 접근 가능. USER 토큰이면 403 */
    @GetMapping("/admin/hello")
    public String adminHello(Authentication authentication) {
        return "관리자 전용 응답: " + authentication.getName();
    }
}
