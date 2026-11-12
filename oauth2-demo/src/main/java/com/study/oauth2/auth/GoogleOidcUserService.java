package com.study.oauth2.auth;

import com.study.oauth2.user.Role;
import com.study.oauth2.user.User;
import com.study.oauth2.user.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * ⭐ 우리가 직접 짠 코드는 사실상 이것 하나. 나머지 OAuth2 흐름은 Spring Security가 처리한다.
 *
 * 이 메서드가 불리는 시점에는 Spring이 이미 다음을 끝냈다:
 *   ① Google이 돌려준 state가 우리가 보낸 것과 같은지 확인 (CSRF 방어)
 *   ② code + client-secret으로 Google 토큰 엔드포인트에서 Access Token, ID Token 받기 (서버↔Google 직통)
 *   ③ ID Token(JWT) 검증: Google 공개키(JWKS)로 RS256 서명 확인 + iss, aud(우리 client-id), exp, nonce
 * → jwt-demo의 verify()와 같은 일을, 비밀키 대신 "Google의 공개키"로 한다.
 *
 * 우리가 할 일: "Google이 확인해준 이 사람"을 우리 회원과 연결하고, 우리 권한을 붙인다.
 */
@Service
public class GoogleOidcUserService extends OidcUserService {

    private final UserRepository userRepository;
    private final String adminEmail;

    public GoogleOidcUserService(UserRepository userRepository,
                                 @Value("${app.admin-email:}") String adminEmail) {
        this.userRepository = userRepository;
        this.adminEmail = adminEmail;
    }

    @Override
    @Transactional
    public OidcUser loadUser(OidcUserRequest userRequest) {
        // ④ 부모 클래스: Google UserInfo 엔드포인트를 Access Token으로 호출해서 프로필 보강, sub 일치 확인
        OidcUser googleUser = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId(); // "google"
        String providerId = googleUser.getSubject();                               // ID Token의 sub

        // ⑤ 처음 보는 sub면 자동 회원가입, 아니면 프로필 갱신
        //    (실무에서는 email_verified=true인지도 확인한다. 인증 안 된 이메일로 남의 계정에 연결되는 것 방지)
        User user = userRepository.findByProviderAndProviderId(provider, providerId)
                .map(existing -> {
                    existing.updateProfile(googleUser.getEmail(), googleUser.getFullName());
                    return existing;
                })
                .orElseGet(() -> userRepository.save(new User(
                        provider, providerId, googleUser.getEmail(), googleUser.getFullName(), roleFor(googleUser.getEmail()))));

        // ⑥ 권한은 Google이 아니라 우리 DB 값으로. 이 객체가 세션에 저장되고 매 요청의 Authentication이 된다
        return new DefaultOidcUser(
                List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name())),
                googleUser.getIdToken(),
                googleUser.getUserInfo(),
                "email"); // authentication.getName()이 이메일을 돌려주도록
    }

    private Role roleFor(String email) {
        return !adminEmail.isBlank() && adminEmail.equalsIgnoreCase(email) ? Role.ADMIN : Role.USER;
    }
}
