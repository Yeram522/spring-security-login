package hashsnap.login.conifg;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
                // CORS 설정 추가
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // JWT 방식이므로 CSRF 완전 비활성화
                .csrf(AbstractHttpConfigurer::disable)

                // Stateless 세션 관리 (JWT 사용)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(authz -> authz
                        // === 정적 리소스 ===
                        .requestMatchers("/css/**", "/js/**", "/images/**").permitAll()

                        // === 웹 페이지 (Thymeleaf 템플릿) ===
                        .requestMatchers("/login", "/register", "/", "/userPage","/findPwd").permitAll()

                        // === Public API (인증 불필요) ===
                        .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()           // 로그인
                        .requestMatchers(HttpMethod.GET, "/api/users").permitAll()                // 이메일 중복확인
                        .requestMatchers(HttpMethod.POST, "/api/users").permitAll()               // 회원가입
                        .requestMatchers(HttpMethod.POST, "/api/email-verification").permitAll()  // 이메일 인증
                        .requestMatchers(HttpMethod.PUT, "/api/users/password").permitAll()     // 비밀번호 재설정
                        

                        // === Private API (JWT 인증 필요) ===
                        .requestMatchers("/api/auth/refresh").authenticated()  // 토큰 갱신
                        .requestMatchers("/api/auth/logout").authenticated()   // 로그아웃
                        .requestMatchers("/api/**").authenticated()            // 기타 모든 API

                        // === 나머지 ===
                        .anyRequest().authenticated()
                )

                // JWT 필터 추가
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                ;

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 허용할 오리진 (개발환경)
        configuration.setAllowedOriginPatterns(Arrays.asList(
                "http://localhost:*",
                "https://localhost:*"
        ));

        // 허용할 HTTP 메서드
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "OPTIONS"
        ));

        // 허용할 헤더
        configuration.setAllowedHeaders(Arrays.asList("*"));

        // 인증 정보 포함 허용 (JWT는 헤더로 전송되므로 false로 설정 가능)
        configuration.setAllowCredentials(false);

        // 모든 경로에 CORS 설정 적용
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}