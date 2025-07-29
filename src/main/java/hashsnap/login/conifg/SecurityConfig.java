package hashsnap.login.conifg;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/**")
                )
                .authorizeHttpRequests(authz -> authz
                        // === 정적 리소스 (항상 허용) ===
                        .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()

                        // === 웹 페이지 (로그인 관련만 허용) ===
                        .requestMatchers("/login", "/register").permitAll()

                        // === API - 인증 불필요 (Public API) ===
                        .requestMatchers(HttpMethod.POST, "/api/auth").permitAll()           // 로그인/로그아웃
                        .requestMatchers(HttpMethod.GET, "/api/users").permitAll()           // 이메일 중복확인
                        .requestMatchers(HttpMethod.POST, "/api/users").permitAll()          // 회원가입
                        .requestMatchers(HttpMethod.POST, "/api/email-verification").permitAll() // 이메일 인증

                        // === API - 인증 필요 (Private API) ===
                        .requestMatchers("/api/**").authenticated()

                        // === 나머지 모든 요청 ===
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/userPage", true)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                        .permitAll()
                );

        return http.build();
    }
}