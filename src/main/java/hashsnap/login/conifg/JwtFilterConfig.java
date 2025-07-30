package hashsnap.login.conifg;

import hashsnap.global.util.JwtUtil;
import hashsnap.login.service.UserAuthenticationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtFilterConfig {

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtUtil jwtUtil, UserAuthenticationService userAuthenticationService) {
        return new JwtAuthenticationFilter(jwtUtil, userAuthenticationService);
    }
}