package com.study.oauth2.user;

import jakarta.persistence.*;

/**
 * session-demo / jwt-demo의 User와 비교: ⭐ password 컬럼이 없다.
 * 비밀번호는 Google이 확인한다. 우리는 "Google의 몇 번 사용자인지(sub)"만 기억한다.
 */
@Entity
@Table(name = "users", uniqueConstraints = @UniqueConstraint(columnNames = {"provider", "providerId"}))
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // 어느 회사 로그인인가: "google" (나중에 "kakao", "naver"가 추가될 수 있음)
    @Column(nullable = false)
    private String provider;

    // ⭐ Google 안에서의 사용자 고유 ID (ID Token의 sub). 회원 식별은 이걸로 한다.
    //    이메일은 사용자가 바꿀 수 있어서 식별자로 쓰면 안 된다.
    @Column(nullable = false)
    private String providerId;

    @Column(nullable = false)
    private String email;

    private String name;

    // 권한은 Google이 아니라 우리 DB가 정한다 (인증은 Google, 인가는 우리)
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    protected User() {
    }

    public User(String provider, String providerId, String email, String name, Role role) {
        this.provider = provider;
        this.providerId = providerId;
        this.email = email;
        this.name = name;
        this.role = role;
    }

    /** 다시 로그인할 때 Google 쪽 최신 프로필로 갱신 */
    public void updateProfile(String email, String name) {
        this.email = email;
        this.name = name;
    }

    public Long getId() { return id; }
    public String getProvider() { return provider; }
    public String getProviderId() { return providerId; }
    public String getEmail() { return email; }
    public String getName() { return name; }
    public Role getRole() { return role; }
}
