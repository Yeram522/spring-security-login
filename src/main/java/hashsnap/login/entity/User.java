package hashsnap.login.entity;

import jakarta.persistence.*;

import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "username", length = 50, nullable = false, unique = true)
    private String username; // 로그인 아이디

    @Column(name = "nickname", length = 50, nullable = false, unique = true)
    private String nickname; // 닉네임/표시명

    @Column(name = "password", length = 100, nullable = false)
    private String password; // BCrypt 암호화된 비밀번호

    @Column(name = "phone", length = 20, nullable = false)
    private String phone; // 휴대폰 번호

    @Column(name = "email", length = 100, nullable = false, unique = true)
    private String email; // 이메일 주소

    // 계정 상태 관리
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    @Builder.Default
    private UserStatus status = UserStatus.ACTIVE; // 계정 상태

    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private Boolean enabled = true; // 계정 활성화 여부

    // 보안 관련
    @Column(name = "login_failure_count", nullable = false)
    @Builder.Default
    private Integer loginFailureCount = 0; // 로그인 실패 횟수 (5회 초과시 잠금)

    @Column(name = "email_verified", nullable = false)
    @Builder.Default
    private Boolean emailVerified = false; // 이메일 인증 여부

    // 토큰 관련
    @Column(name = "refresh_token", length = 500)
    private String refreshToken;

    @Column(name = "refresh_token_expires_at")
    private LocalDateTime refreshTokenExpiresAt;

    // 시간 관리
    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt; // 마지막 로그인 시간

    @Column(name = "password_changed_at", nullable = false)
    @Builder.Default
    private LocalDateTime passwordChangedAt = LocalDateTime.now(); // 비밀번호 변경 시간

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt; // 계정 생성 시간

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt; // 정보 수정 시간

    // 계정 상태 열거형
    public enum UserStatus {
        ACTIVE("활성"),
        SUSPENDED("정지"),
        DELETED("삭제");

        private final String description;

        UserStatus(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    // 편의 메서드들 - 사용 안할 시 지울 예쩡
    public boolean isAccountLocked() {
        return loginFailureCount >= 5;
    }

    public boolean isAccountActive() {
        return status == UserStatus.ACTIVE && enabled;
    }

    public void incrementLoginFailureCount() {
        this.loginFailureCount++;
    }

    public void resetLoginFailureCount() {
        this.loginFailureCount = 0;
    }

    public void updateLastLoginTime() {
        this.lastLoginAt = LocalDateTime.now();
    }
}