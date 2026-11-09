package com.study.session.api;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DemoController {

    /**
     * 로그인한 사용자 누구나 접근 가능.
     * Authentication은 필터가 "세션에서 꺼낸" SecurityContext에서 주입된다.
     */
    @GetMapping("/me")
    public Map<String, Object> me(Authentication authentication, HttpSession session) {
        return Map.of(
                "email", authentication.getName(),
                "roles", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList(),
                // ⚠️ 학습용: 서버에 세션이 실제로 존재한다는 걸 보여주려고 노출. 실서비스에서는 절대 응답에 넣지 않는다.
                "sessionId", session.getId(),
                "sessionCreatedAt", Instant.ofEpochMilli(session.getCreationTime()).toString(),
                "sessionTimeoutSeconds", session.getMaxInactiveInterval()
        );
    }

    /** ADMIN만 접근 가능. USER로 로그인하면 403 */
    @GetMapping("/admin/hello")
    public String adminHello(Authentication authentication) {
        return "관리자 전용 응답: " + authentication.getName();
    }
}
