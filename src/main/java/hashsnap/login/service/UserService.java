package hashsnap.login.service;

import hashsnap.login.dto.SignupRequestDto;
import hashsnap.login.entity.User;
import hashsnap.login.repository.UserRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;

    private final UserRepository userRepository;

    @Transactional
    public void signup(@Valid SignupRequestDto signupRequest) {
        // 원본 비밀번호
        String rawPassword = signupRequest.getPassword();
        // 원본 비밀번호를 암호화
        String encodedPassword = passwordEncoder.encode(rawPassword);

        User user =  User.builder()
                .username(signupRequest.getUsername())
                .nickname(signupRequest.getNickname())
                .password(encodedPassword)
                .phone(signupRequest.getPhone())
                .email(signupRequest.getEmail())
                .build();

        userRepository.save(user);
    }

    public User findByEmail(String email) {
        // JPA로 사용자 조회
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + email));
    }

    public boolean isEmailExists(String email) {

        return userRepository.existsByEmail(email);
    }

    public void resetPassword(@NotBlank(message = "이메일을 입력해주세요") @Email(message = "올바른 이메일 형식이 아닙니다") String email,
                              @NotBlank(message = "새 비밀번호를 입력해주세요")
                              @Size(min = 8, message = "비밀번호는 8자 이상이어야 합니다") String newPassword) {
        // 새로운 비밀번호를 암호화
        String encodedPassword = passwordEncoder.encode(newPassword);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + email));

        user.setPassword(encodedPassword); //update
    }
}
