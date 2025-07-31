package hashsnap.login.conifg;

import hashsnap.global.util.JwtUtil;
import hashsnap.login.service.UserAuthenticationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * JWT 필터 설정 클래스
 * JwtAuthenticationFilter Bean 등록
 * Spring Security와 JWT 유틸 간 순환 참조 문제 해결
 */
@Configuration
public class JwtFilterConfig {

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtUtil jwtUtil, UserAuthenticationService userAuthenticationService) {
        return new JwtAuthenticationFilter(jwtUtil, userAuthenticationService);
    }
}