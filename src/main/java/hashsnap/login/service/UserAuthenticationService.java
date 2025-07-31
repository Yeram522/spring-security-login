package hashsnap.login.service;

import hashsnap.login.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Spring Security용 사용자 인증 서비스
 * 이메일로 사용자를 조회하고 UserDetails 객체로 변환하여 반환
 * 모든 사용자에게 기본적으로 ROLE_USER 권한을 부여함
 */

@Service
@RequiredArgsConstructor
public class UserAuthenticationService implements UserDetailsService {

    private final UserService userService;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // Spring Security의 username 파라미터로 이메일을 받음
        // JPA로 사용자 조회
        User user = userService.findByEmail(email);

        // User 엔티티를 Spring Security의 UserDetails로 변환
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())           // 사용자명 (이메일)
                .password(user.getPassword())        // 암호화된 비밀번호
                .authorities("ROLE_USER")            // 권한 (모든 사용자에게 USER 권한)
                .accountExpired(false)               // 계정 만료 여부
                .accountLocked(false)                // 계정 잠김 여부
                .credentialsExpired(false)           // 비밀번호 만료 여부
                .disabled(false)                     // 계정 비활성화 여부
                .build();
    }
}
