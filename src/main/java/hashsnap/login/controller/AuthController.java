package hashsnap.login.controller;

import hashsnap.global.controller.ApiController;
import hashsnap.global.response.ApiResponse;
import hashsnap.global.util.ResponseUtils;
import hashsnap.login.dto.EmailVerificationDto;
import hashsnap.login.dto.LoginRequestDto;
import hashsnap.login.dto.LoginResponseDto;
import hashsnap.login.dto.TokenRefreshResponseDto;
import hashsnap.login.exception.EmailVerificationException;
import hashsnap.login.service.AuthService;
import hashsnap.login.service.EmailVerificationService;
import hashsnap.login.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 인증 API 컨트롤러
 * JWT 기반 로그인, 토큰 갱신, 로그아웃 처리, 이메일 인증
 * HttpOnly 쿠키를 통한 안전한 RefreshToken 관리
 */
@RestController
@Slf4j
@RequiredArgsConstructor
public class AuthController extends ApiController {

    private final AuthService authService;
    private final UserService userService;
    private final EmailVerificationService emailVerificationService;

    /**
     * 로그인 API
     * @param loginRequestDto 로그인 요청 DTO
     * @param response Refresh Token을 HttpOnly 쿠키로 설정 목적
     * @return response message
     */
    @PostMapping("/auth/login")
    public ResponseEntity<ApiResponse<LoginResponseDto>> login(
            @Valid @RequestBody LoginRequestDto loginRequestDto,
            HttpServletResponse response) {

        LoginResponseDto loginResponse = authService.login(loginRequestDto);

        // Refresh Token을 HttpOnly 쿠키에 저장 (보안상 응답에서 제외)
        addRefreshTokenCookie(response, loginResponse.getRefreshToken());

        // 응답에서는 Refresh Token 제외
        LoginResponseDto safeResponse = LoginResponseDto.builder()
                .accessToken(loginResponse.getAccessToken())
                .userEmail(loginResponse.getUserEmail())
                .build();

        return ResponseUtils.ok("로그인이 완료되었습니다", safeResponse);
    }

    /**
     * 리프레시 토큰 요청 API
     * @param request Refresh Token을 쿠키에서 꺼내는 용도.
     * @return result message
     */
    @PostMapping("/auth/refresh")
    public ResponseEntity<ApiResponse<TokenRefreshResponseDto>> refreshToken(HttpServletRequest request) {

        String refreshToken = extractRefreshTokenFromCookie(request);
        String newAccessToken = authService.refreshAccessToken(refreshToken);

        TokenRefreshResponseDto response = TokenRefreshResponseDto.builder()
                .accessToken(newAccessToken)
                .build();

        return ResponseUtils.ok("토큰이 갱신되었습니다", response);
    }

    /**
     * 로그아웃 API
     * @param request Refresh Token을 쿠키에서 가져오기 위한 용도.
     * @param response Refresh Token을 만료시키기 위한 용도.
     * @return result message
     */
    @PostMapping("/auth/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        String refreshToken = extractRefreshTokenFromCookie(request);
        authService.logout(refreshToken);

        // Refresh Token 쿠키 삭제
        removeRefreshTokenCookie(response);

        return ResponseUtils.ok("로그아웃이 완료되었습니다");
    }

    /**
     * 이메일 인증 API( 인증번호 발송, 인증번호 확인 )
     * @param request 이메일 인증 DTO
     * @return result message
     */
    @PostMapping("/auth/email-verification")
    public ResponseEntity<ApiResponse<Void>> handleEmailVerification(@Valid @RequestBody EmailVerificationDto request) {
        try {
            return switch (request.getAction()) {
                case "send" -> handleSendAction(request);
                case "verify" -> handleVerifyAction(request);
                default -> ResponseUtils.badRequest("잘못된 요청입니다");
            };
        } catch (EmailVerificationException e) {
            return ResponseUtils.badRequest(e.getMessage());
        } catch (Exception e) {
            log.error("이메일 인증 처리 중 오류 발생", e);
            return ResponseUtils.internalServerError("처리 중 오류가 발생했습니다");
        }
    }

    /**
     * 이메일 인증 헬퍼 메서드
     * case: 'send'
     * 인증번호 전송
     * @param request 이메일 인증 DTO
     * @return result message
     */
    private ResponseEntity<ApiResponse<Void>> handleSendAction(EmailVerificationDto request) {
        if ("password-reset".equals(request.getPurpose()) && !userService.isEmailExists(request.getEmail())) {
            return ResponseUtils.badRequest("존재하지 않는 메일입니다");
        }

        emailVerificationService.sendVerificationCode(request.getEmail(), request.getPurpose());
        return ResponseUtils.ok("인증번호가 발송되었습니다");
    }

    /**
     * 이메일 인증 헬퍼 메서드
     * case: 'verify'
     * 인증번호 검증
     * @param request 이메일 인증 DTO
     * @return result message
     */
    private ResponseEntity<ApiResponse<Void>> handleVerifyAction(EmailVerificationDto request) {
        if (request.getVerificationCode() == null || request.getVerificationCode().trim().isEmpty()) {
            return ResponseUtils.badRequest("인증번호를 입력해주세요");
        }

        boolean isValid = emailVerificationService.verifyCode(
                request.getEmail(),
                request.getVerificationCode().trim(),
                request.getPurpose()
        );

        return isValid
                ? ResponseUtils.ok("인증이 완료되었습니다")
                : ResponseUtils.badRequest("인증번호가 일치하지 않습니다");
    }

    // === 쿠키 관련 헬퍼 메서드들 (Controller 책임) ===

    /**
     * Refresh Token 쿠키 추가
     */
    private void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);      // JavaScript 접근 차단
        cookie.setSecure(true);        // HTTPS에서만 전송 (개발 시에는 false로 설정)
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7일
        response.addCookie(cookie);
    }

    /**
     * Refresh Token 쿠키 삭제
     */
    private void removeRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0); // 즉시 만료
        response.addCookie(cookie);
    }

    /**
     * 쿠키에서 Refresh Token 추출
     */
    private String extractRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
