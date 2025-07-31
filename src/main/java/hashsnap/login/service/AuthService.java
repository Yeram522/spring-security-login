package hashsnap.login.service;

import hashsnap.global.util.JwtUtil;
import hashsnap.login.dto.LoginRequestDto;
import hashsnap.login.dto.LoginResponseDto;
import hashsnap.login.entity.User;
import hashsnap.login.exception.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 인증 비즈니스 로직 서비스
 * Spring Security 기반 사용자 인증 및 JWT 토큰 관리
 * 로그인, 토큰 갱신, 로그아웃 프로세스 담당
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    /**
     * 로그인 처리
     */
    public LoginResponseDto login(LoginRequestDto loginRequestDto) {
        String email = loginRequestDto.getEmail();

        try {
            // 1. 로그인 시도 전 계정 잠금 상태 확인
            User user = userService.findByEmail(email);
            if (user != null && user.getLoginFailureCount() >= 5) {
                throw new AuthException.AccountLockedException("계정이 잠겨있습니다. 관리자에게 문의하세요.");
            }

            // 2. 인증 시도
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequestDto.getEmail(),
                            loginRequestDto.getPassword()
                    )
            );

            // 3. 인증 성공 시 실패 카운트 리셋
            if (user != null) {
                userService.resetLoginFailureCount(email);
            }

            // 토큰 생성
            String accessToken = jwtUtil.createAccessToken(email);
            String refreshToken = jwtUtil.createRefreshToken(email);

            // Refresh Token DB에 저장
            refreshTokenService.saveRefreshToken(email, refreshToken);

            log.info("로그인 성공: {}", email);

            return LoginResponseDto.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .userEmail(email)
                    .build();

        } catch (BadCredentialsException e) {
            // 4. 인증 실패 시 실패 카운트 증가
            userService.incrementLoginFailureCount(email);
            log.warn("로그인 실패 - 잘못된 인증 정보: {} (실패 횟수 증가)", email);
            throw new AuthException.InvalidCredentialsException("이메일 또는 비밀번호가 올바르지 않습니다");
        }catch (UsernameNotFoundException e){
            log.warn("로그인 실패 - 존재하지 않는 유저: {}", email);
            throw new AuthException.InvalidCredentialsException("이메일 또는 비밀번호가 올바르지 않습니다");
        }
    }

    /**
     * 토큰 갱신
     */
    public String refreshAccessToken(String refreshToken) {
        // 토큰 유효성 검증
        if (refreshToken == null) {
            throw new AuthException.InvalidTokenException("Refresh Token이 없습니다");
        }

        if (!jwtUtil.validateToken(refreshToken)) {
            throw new AuthException.TokenExpiredException("유효하지 않은 Refresh Token입니다");
        }

        String email = jwtUtil.getEmail(refreshToken);

        // DB에 저장된 Refresh Token과 비교
        if (!refreshTokenService.validateRefreshToken(email, refreshToken)) {
            throw new AuthException.InvalidTokenException("Refresh Token이 일치하지 않습니다");
        }

        // 새로운 Access Token 생성
        String newAccessToken = jwtUtil.createAccessToken(email);
        log.info("토큰 갱신 완료: {}", email);

        return newAccessToken;
    }

    /**
     * 로그아웃 처리
     */
    public void logout(String refreshToken) {
        if (refreshToken != null && jwtUtil.validateToken(refreshToken)) {
            String email = jwtUtil.getEmail(refreshToken);
            refreshTokenService.deleteRefreshToken(email);
            log.info("로그아웃 완료: {}", email);
        }
    }
}
