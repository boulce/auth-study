package com.study.jwt.auth;

import com.study.jwt.jwt.InvalidTokenException;
import com.study.jwt.user.Role;
import com.study.jwt.user.User;
import com.study.jwt.user.UserRepository;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService;

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder,
                          AuthenticationManager authenticationManager,
                          TokenService tokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.tokenService = tokenService;
    }

    /** session-demo와 완전히 같다. 가입은 인증 방식과 무관 */
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody @Valid SignupRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("이미 가입된 이메일");
        }
        userRepository.save(new User(request.email(), passwordEncoder.encode(request.password()), Role.USER));
        return ResponseEntity.status(HttpStatus.CREATED).body("가입 완료");
    }

    @PostMapping("/login")
    public TokenResponse login(@RequestBody @Valid LoginRequest request) {
        // ① 인증: session-demo와 똑같다 (DB 조회 → BCrypt.matches). 로그인 순간에는 JWT도 DB를 본다.
        Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(request.email(), request.password()));

        // ② 여기부터 다르다. 세션에 저장(saveContext)하는 대신 토큰을 만들어 body로 돌려준다.
        //    서버는 Access Token을 어디에도 저장하지 않는다.
        return tokenService.issue(authentication.getName());
    }

    /** Access 만료 시 호출. 인증 필요 없음(permitAll) — Access가 이미 만료된 상태에서 부르니까 */
    @PostMapping("/refresh")
    public TokenResponse refresh(@RequestBody @Valid RefreshRequest request) {
        return tokenService.refresh(request.refreshToken());
    }

    /** Access Token으로 인증된 요청만 가능. 서버의 Refresh를 지운다 */
    @PostMapping("/logout")
    public String logout(Authentication authentication) {
        tokenService.logout(authentication.getName());
        return "로그아웃: Refresh Token 삭제됨. 이미 발급된 Access Token은 만료 시각까지 유효 (클라이언트가 지워야 함)";
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<String> handleLoginFailure(AuthenticationException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("이메일 또는 비밀번호가 올바르지 않습니다");
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<String> handleInvalidToken(InvalidTokenException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰 거부: " + e.getMessage());
    }
}
