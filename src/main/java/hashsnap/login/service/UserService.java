package hashsnap.login.service;

import hashsnap.login.dto.SignupRequestDto;
import hashsnap.login.dto.UserInfoResponseDto;
import hashsnap.login.entity.User;
import hashsnap.login.repository.UserRepository;
import hashsnap.login.exception.EmailVerificationException;
import hashsnap.login.exception.UserException.DuplicateUserException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final EmailVerificationService emailVerificationService;
    private final UserRepository userRepository;

    /**
     * 회원가입
     */
    @Transactional
    public void signup(@Valid SignupRequestDto signupRequest) {
        log.info("회원가입 시작: email={}", signupRequest.getEmail());

        // 1. 이메일 인증 확인
        if (!emailVerificationService.isEmailVerified(signupRequest.getEmail(), "signup")) {
            log.warn("이메일 인증 미완료: email={}", signupRequest.getEmail());
            throw new EmailVerificationException("이메일 인증을 완료해주세요");
        }

        // 2. 중복 사용자 확인
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            log.warn("이메일 중복: email={}", signupRequest.getEmail());
            throw new DuplicateUserException("이미 존재하는 이메일입니다");
        }

        // 3. 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(signupRequest.getPassword());

        // 4. 사용자 저장
        User user = User.builder()
                .username(signupRequest.getUsername())
                .nickname(signupRequest.getNickname())
                .password(encodedPassword)
                .phone(signupRequest.getPhone())
                .emailVerified(true)
                .email(signupRequest.getEmail())
                .build();

        userRepository.save(user);
        log.info("회원가입 완료: email={}", signupRequest.getEmail());
    }

    /**
     * 사용자 정보 조회 (응답 DTO로 반환)
     */
    public UserInfoResponseDto getUserInfo(String email) {
        log.debug("사용자 정보 조회: email={}", email);

        if (email == null || email.trim().isEmpty()) {
            log.warn("이메일이 null 또는 비어있음");
            throw new IllegalArgumentException("이메일은 필수입니다");
        }

        User user = userRepository.findActiveUserByEmail(email)
                .orElseThrow(() -> {
                    log.warn("사용자를 찾을 수 없음: email={}", email);
                    return new UsernameNotFoundException("사용자를 찾을 수 없습니다");
                });

        log.debug("사용자 정보 조회 완료: email={}", email);
        return UserInfoResponseDto.from(user);
    }

    /**
     * 사용자 엔티티 조회 (내부 사용용)
     */
    public User findByEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            log.warn("이메일이 null 또는 비어있음");
            throw new IllegalArgumentException("이메일은 필수입니다");
        }

        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("사용자를 찾을 수 없음: email={}", email);
                    return new UsernameNotFoundException("사용자를 찾을 수 없습니다");
                });
    }

    /**
     * 이메일 중복 확인
     */
    public boolean isEmailExists(String email) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }
        return userRepository.existsByEmail(email);
    }

    /**
     * 비밀번호 재설정
     */
    @Transactional
    public void resetPassword(@NotBlank(message = "이메일을 입력해주세요")
                              @Email(message = "올바른 이메일 형식이 아닙니다") String email,
                              @NotBlank(message = "새 비밀번호를 입력해주세요")
                              @Size(min = 8, message = "비밀번호는 8자 이상이어야 합니다") String newPassword) {

        log.info("비밀번호 재설정 시작: email={}", email);

        // 이메일 인증 확인
        if (!emailVerificationService.isEmailVerified(email, "password-reset")) {
            log.warn("이메일 인증 미완료: email={}", email);
            throw new EmailVerificationException("이메일 인증을 완료해주세요");
        }

        User user = findByEmail(email);

        // 새로운 비밀번호를 암호화
        String encodedPassword = passwordEncoder.encode(newPassword);

        user.setLoginFailureCount(0);
        user.setStatus(User.UserStatus.ACTIVE);
        user.setPassword(encodedPassword);

        log.info("비밀번호 재설정 완료: email={}", email);
    }

    /**
     * 로그인 실패 카운트 리셋
     */
    @Transactional
    public void resetLoginFailureCount(String email) {
        log.debug("로그인 실패 카운트 리셋: email={}", email);

        User user = findByEmail(email);
        if (user.getLoginFailureCount() > 0) {
            user.setLoginFailureCount(0);
            log.info("로그인 실패 카운트 리셋 완료: email={}", email);
        }
    }

    /**
     * 로그인 실패 카운트 증가
     */
    @Transactional
    public void incrementLoginFailureCount(String email) {
        log.debug("로그인 실패 카운트 증가: email={}", email);

        User user = findByEmail(email);
        int newCount = user.getLoginFailureCount() + 1;

        // 5회 이상 실패 시 계정 잠금
        if (newCount >= 5) {
            user.setStatus(User.UserStatus.SUSPENDED);
            user.setEnabled(false);
            log.warn("계정 잠금 처리: email={}, 실패횟수={}", email, newCount);
        }

        user.setLoginFailureCount(newCount);
        log.info("로그인 실패 카운트 업데이트: email={}, count={}", email, newCount);
    }

}
