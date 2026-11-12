package com.study.oauth2.api;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class DemoController {

    /** session-demo / jwt-demo의 /api/me와 같은 API. 사용자 정보의 출처가 Google ID Token이라는 점만 다르다 */
    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal OidcUser user, Authentication authentication) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", authentication.getName());
        body.put("name", user.getFullName());
        body.put("roles", authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        body.put("googleSub", user.getSubject());
        body.put("idTokenIssuer", user.getIssuer().toString());
        body.put("idTokenAudience", user.getAudience());
        body.put("howServerKnowsYou", "Google이 확인 → ID Token 검증 → 우리 서버 세션(JSESSIONID)");
        return body;
    }

    @GetMapping("/admin/hello")
    public String adminHello(Authentication authentication) {
        return "관리자 전용 응답: " + authentication.getName();
    }
}
