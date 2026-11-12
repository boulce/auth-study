package com.study.oauth2.api;

import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

/** 브라우저로 직접 눌러보기 위한 최소 화면 */
@RestController
public class HomeController {

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public String home(@AuthenticationPrincipal OidcUser user) {
        if (user == null) {
            return """
                    <h1>oauth2-demo</h1>
                    <a href="/oauth2/authorization/google">Google로 로그인</a>
                    """;
        }
        return """
                <h1>%s 님 로그인됨</h1>
                <p><a href="/api/me">/api/me</a> · <a href="/api/admin/hello">/api/admin/hello</a></p>
                <form method="post" action="/logout"><button>로그아웃</button></form>
                """.formatted(HtmlUtils.htmlEscape(user.getEmail()));
    }
}
