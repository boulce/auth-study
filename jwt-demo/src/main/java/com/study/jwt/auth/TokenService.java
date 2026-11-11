package com.study.jwt.auth;

import com.study.jwt.jwt.InvalidTokenException;
import com.study.jwt.jwt.JwtClaims;
import com.study.jwt.jwt.JwtProperties;
import com.study.jwt.jwt.JwtProvider;
import com.study.jwt.jwt.TokenType;
import com.study.jwt.user.User;
import com.study.jwt.user.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class TokenService {

    private final JwtProvider jwtProvider;
    private final JwtProperties properties;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public TokenService(JwtProvider jwtProvider,
                        JwtProperties properties,
                        RefreshTokenRepository refreshTokenRepository,
                        UserRepository userRepository) {
        this.jwtProvider = jwtProvider;
        this.properties = properties;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
    }

    /** 로그인 성공 직후: Access + Refresh 발급, Refresh만 DB에 저장 */
    @Transactional
    public TokenResponse issue(String email) {
        User user = userRepository.findByEmail(email).orElseThrow();
        String accessToken = jwtProvider.createAccessToken(user.getEmail(), user.getRole());
        String refreshToken = jwtProvider.createRefreshToken(user.getEmail(), user.getRole());
        Instant refreshExpiresAt = Instant.now().plus(properties.refreshTokenValidity());

        refreshTokenRepository.findById(email).ifPresentOrElse(
                saved -> saved.rotate(refreshToken, refreshExpiresAt),
                () -> refreshTokenRepository.save(new RefreshToken(email, refreshToken, refreshExpiresAt)));

        return new TokenResponse("Bearer", accessToken, properties.accessTokenValidity().toSeconds(), refreshToken);
    }

    /**
     * ⭐ Access 만료(401) → 클라이언트가 Refresh를 들고 여기로 → 새 Access + 새 Refresh.
     *
     * Access 검증과 다른 점: 서명·만료 검증에 더해 **DB 조회**를 한다.
     * → 로그아웃·폐기된 Refresh를 막을 수 있고, 권한 변경도 여기서 반영된다 (DB의 최신 role로 새 Access 발급).
     *
     * noRollbackFor: ③에서 delete() 후 예외를 던진다. 기본 @Transactional은 RuntimeException이면 롤백하므로
     * 그대로 두면 "폐기"까지 취소돼서 훔친 사람이 최신 Refresh를 계속 쓸 수 있다. (테스트가 실제로 잡아낸 버그)
     */
    @Transactional(noRollbackFor = InvalidTokenException.class)
    public TokenResponse refresh(String refreshToken) {
        // ① 서명·만료 검증 (Access와 똑같은 verify)
        JwtClaims claims = jwtProvider.verify(refreshToken);
        if (claims.type() != TokenType.REFRESH) {
            throw new InvalidTokenException("Access Token으로는 재발급할 수 없음");
        }

        // ② 서버에 저장된 Refresh인가 (없으면 로그아웃했거나 폐기된 것)
        RefreshToken saved = refreshTokenRepository.findById(claims.email())
                .orElseThrow(() -> new InvalidTokenException("폐기된 Refresh Token (로그아웃 등)"));

        // ③ 재사용 감지: 서명은 맞는데 저장된 최신 값과 다르다 = 이미 한 번 쓰고 교체된 예전 Refresh.
        //    정상 사용자는 예전 걸 다시 쓸 일이 없다 → 누군가 훔쳐서 쓰는 것으로 보고 전부 폐기 (정상 사용자도 재로그인)
        if (!saved.getToken().equals(refreshToken)) {
            refreshTokenRepository.delete(saved);
            throw new InvalidTokenException("이미 사용된 Refresh Token 재사용 감지 → 이 사용자의 Refresh 전부 폐기");
        }

        // ④ Rotation: 새 Access와 함께 새 Refresh도 발급하고 DB 값을 교체
        return issue(claims.email());
    }

    /** 로그아웃: 서버가 할 수 있는 건 Refresh 삭제뿐. 이미 나간 Access는 못 회수한다 */
    @Transactional
    public void logout(String email) {
        refreshTokenRepository.deleteById(email);
    }
}
