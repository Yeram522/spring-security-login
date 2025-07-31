package hashsnap.login.service;

import hashsnap.login.dto.SignupRequestDto;
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
        // 1. 이메일 인증 확인
        if (!emailVerificationService.isEmailVerified(signupRequest.getEmail(), "signup")) {
            throw new EmailVerificationException("이메일 인증을 완료해주세요");
        }

        // 2. 중복 사용자 확인
        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new DuplicateUserException("이미 존재하는 이메일입니다");
        }

        // 3. 비밀번호 암호화
        // 원본 비밀번호
        String rawPassword = signupRequest.getPassword();
        // 원본 비밀번호를 암호화
        String encodedPassword = passwordEncoder.encode(rawPassword);

        // 4. 사용자 저장
        User user =  User.builder()
                .username(signupRequest.getUsername())
                .nickname(signupRequest.getNickname())
                .password(encodedPassword)
                .phone(signupRequest.getPhone())
                .emailVerified(true)
                .email(signupRequest.getEmail())
                .build();

        userRepository.save(user);
    }

    /**
     * 유저 정보 조회
     */
    public User findByEmail(String email) {
        // JPA로 사용자 조회
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + email));
    }

    /**
     * 이메일 중복 조회
     */
    public boolean isEmailExists(String email) {

        return userRepository.existsByEmail(email);
    }

    /**
     * 비밀번호 업데이트
     */
    @Transactional
    public void resetPassword(@NotBlank(message = "이메일을 입력해주세요") @Email(message = "올바른 이메일 형식이 아닙니다") String email,
                              @NotBlank(message = "새 비밀번호를 입력해주세요")
                              @Size(min = 8, message = "비밀번호는 8자 이상이어야 합니다") String newPassword) {
        // 새로운 비밀번호를 암호화
        String encodedPassword = passwordEncoder.encode(newPassword);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + email));

        user.setLoginFailureCount(0);
        user.setPassword(encodedPassword); //update
    }

    /**
     * 계정 잠금
     */
    @Transactional
    public void resetLoginFailureCount(String email) {
        User user = findByEmail(email);
        if (user != null && user.getLoginFailureCount() > 0) {
            user.setLoginFailureCount(0);
            userRepository.save(user);
            log.info("로그인 실패 카운트 리셋: {}", email);
        }
    }

    /**
     * 로그인 실패 카운트
     */
    @Transactional
    public void incrementLoginFailureCount(String email) {
        User user = findByEmail(email);
        if (user != null) {
            int newCount = user.getLoginFailureCount() + 1;

            // 5회 이상 실패 시 계정 잠금
            if (newCount >= 5) {
                user.setStatus(User.UserStatus.SUSPENDED);
                user.setEnabled(false);
                log.warn("계정 잠금 처리: {} (실패 횟수: {})", email, newCount);
            }

            user.setLoginFailureCount(newCount);
            userRepository.save(user);
        }
    }
}
