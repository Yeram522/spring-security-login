package hashsnap.login.conifg;

import hashsnap.security.filter.SecurityAuditFilter;
import jakarta.servlet.http.HttpServletResponse;
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

/**
 * Spring Security 보안 설정
 * JWT 인증 필터 체인 구성 및 URL별 접근 권한 설정
 * CSRF 보호, CORS 설정, 폼 로그인 비활성화 등 API 서버 최적화
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter
                                            , SecurityAuditFilter securityAuditFilter) throws Exception {
        http
                // CORS 설정
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // JWT 방식이므로 CSRF 완전 비활성화
                .csrf(AbstractHttpConfigurer::disable)

                // Stateless 세션 관리 (JWT 사용)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // JWT 필터 (인증)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

                // 모든 요청 로깅
                .addFilterBefore(securityAuditFilter, UsernamePasswordAuthenticationFilter.class)

                .authorizeHttpRequests(authz -> authz
                        // === 정적 리소스 ===
                        .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico").permitAll()

                        // === HTML 페이지 ===
                        .requestMatchers("/", "/login", "/register", "/findPwd", "/userPage","/admin").permitAll()

                        // === Public API (인증 불필요) ===
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()           // 로그인
                        .requestMatchers(HttpMethod.GET, "/api/v1/users").permitAll()                // 이메일 중복확인
                        .requestMatchers(HttpMethod.POST, "/api/v1/users").permitAll()               // 회원가입
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/email/send").permitAll()     // 이메일 발송
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/email/verify").permitAll()   // 이메일 인증
                        .requestMatchers(HttpMethod.PUT, "/api/v1/users/password").permitAll()       // 비밀번호 재설정

                        // === SSE 스트림만 예외 처리 ===
                        .requestMatchers("/api/v1/admin/security/alerts/stream").permitAll()

                        // === 관리자 전용 API === 👈
                        .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")

                        // === 일반 사용자 API (JWT 토큰 + USER 또는 ADMIN 권한 필요) ===
                        .requestMatchers(HttpMethod.GET, "/api/v1/users/me").hasAnyRole("USER", "ADMIN")          // 내 정보 조회

                        // === 인증만 필요한 API (권한 상관없이 로그인만 되면 됨) ===
                        .requestMatchers("/api/v1/auth/refresh").authenticated()                      // 토큰 갱신
                        .requestMatchers("/api/v1/auth/logout").authenticated()                       // 로그아웃

                        // === 기타 모든 API (인증 필요) ===
                        .requestMatchers("/api/v1/**").authenticated()

                        // === 나머지 모든 요청 (인증 필요) ===
                        .anyRequest().authenticated()
                )

                // 예외 처리
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((request, response, authException) -> {
                            // API 요청인 경우 JSON 응답
                            if (request.getRequestURI().startsWith("/api/")) {
                                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                                response.setContentType("application/json;charset=UTF-8");
                                response.getWriter().write("{\"success\":false,\"message\":\"인증이 필요합니다.\"}");
                            } else {
                                // HTML 페이지 요청인 경우 로그인 페이지로 리다이렉트
                                response.sendRedirect("/login");
                            }
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            // API 요청인 경우 JSON 응답
                            if (request.getRequestURI().startsWith("/api/")) {
                                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                                response.setContentType("application/json;charset=UTF-8");
                                response.getWriter().write("{\"success\":false,\"message\":\"접근 권한이 없습니다.\"}");
                            } else {
                                // HTML 페이지 요청인 경우 접근 거부 페이지
                                response.sendRedirect("/access-denied");
                            }
                        })
                );

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