package com.study.session.user;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Spring Security가 "이 email의 사용자 정보(해시된 비밀번호, 권한)를 줘"라고 할 때 호출하는 곳.
 * 로그인 시 AuthenticationManager → (여기) DB 조회 → PasswordEncoder.matches() 순서로 쓰인다.
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException(email));

        return org.springframework.security.core.userdetails.User.withUsername(user.getEmail())
                .password(user.getPassword())
                // roles("ADMIN") → 권한 문자열 "ROLE_ADMIN"으로 저장된다. hasRole("ADMIN")이 이걸 검사.
                .roles(user.getRole().name())
                .build();
    }
}
