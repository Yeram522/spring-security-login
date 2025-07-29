package hashsnap.login.service;

import hashsnap.login.dto.SignupRequestDto;
import hashsnap.login.entity.User;
import hashsnap.login.repository.UserRepository;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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

}
