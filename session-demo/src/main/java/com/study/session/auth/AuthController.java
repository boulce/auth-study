package com.study.session.auth;

import com.study.session.user.Role;
import com.study.session.user.User;
import com.study.session.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          AuthenticationManager authenticationManager,
                          SecurityContextRepository securityContextRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody @Valid SignupRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("이미 가입된 이메일");
        }
        // 평문 비밀번호를 BCrypt로 해시해서 저장 (salt가 해시 문자열 안에 포함됨)
        userRepository.save(new User(request.email(), passwordEncoder.encode(request.password()), Role.USER));
        return ResponseEntity.status(HttpStatus.CREATED).body("가입 완료");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody @Valid LoginRequest request,
                                        HttpServletRequest httpRequest,
                                        HttpServletResponse httpResponse) {
        // ① 인증: CustomUserDetailsService로 DB 조회 → PasswordEncoder.matches(평문, 해시) 비교
        //    실패하면 AuthenticationException → 아래 @ExceptionHandler에서 401
        Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(request.email(), request.password()));

        // ② 세션 고정 공격 방어: 로그인 전에 쓰던 세션이 있으면 ID를 새로 바꾼다
        //    (공격자가 미리 심어둔 세션 ID로 피해자가 로그인하는 것을 막음)
        if (httpRequest.getSession(false) != null) {
            httpRequest.changeSessionId();
        }

        // ③ 인증 결과(누구인지 + 권한)를 SecurityContext에 담는다
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        // ④ ⭐ 세션에 저장. 이 순간 서버 메모리에 세션이 생기고, 응답에 Set-Cookie: JSESSIONID=... 가 붙는다
        //    (Spring Security 6부터는 이렇게 명시적으로 저장해야 다음 요청에서도 로그인 상태가 유지됨)
        securityContextRepository.saveContext(context, httpRequest, httpResponse);

        return ResponseEntity.ok("로그인 성공");
    }

    // 로그아웃은 SecurityConfig의 .logout()이 필터에서 처리한다 (컨트롤러 메서드 없음)

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<String> handleLoginFailure(AuthenticationException e) {
        // "이메일이 없음"인지 "비밀번호 틀림"인지 구분해서 알려주지 않는다 → 계정 존재 여부 노출 방지
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("이메일 또는 비밀번호가 올바르지 않습니다");
    }
}
