package com.study.jwt.user;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 403(권한 없음) vs 200 비교를 위해 앱 시작 시 관리자 계정 하나를 넣어둔다. (학습용)
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (!userRepository.existsByEmail("admin@test.com")) {
            userRepository.save(new User("admin@test.com", passwordEncoder.encode("admin1234"), Role.ADMIN));
        }
    }
}
