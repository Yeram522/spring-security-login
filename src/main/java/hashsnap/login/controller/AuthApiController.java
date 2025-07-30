package hashsnap.login.controller;

import hashsnap.global.response.ApiResponse;
import hashsnap.global.util.JwtUtil;
import hashsnap.login.dto.LoginRequest;
import hashsnap.login.service.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class AuthApiController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    // 로그인
    @PostMapping("/auth/login")
    public ResponseEntity<ApiResponse> login(@RequestBody LoginRequest loginRequest,
                                             HttpServletRequest request,
                                             HttpServletResponse response) {
        try {
            // 인증 시도
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String email = userDetails.getUsername();

            // 토큰 생성
            String accessToken = jwtUtil.createAccessToken(email);
            String refreshToken = jwtUtil.createRefreshToken(email);

            // Refresh Token DB에 저장
            refreshTokenService.saveRefreshToken(email, refreshToken);

            // Refresh Token을 HttpOnly 쿠키에 저장
            addRefreshTokenCookie(response, refreshToken);


            // 응답 데이터 구성
            Map<String, String> data = new HashMap<>();
            data.put("accessToken", accessToken);
            data.put("userEmail", email);

            return ResponseEntity.ok(
                    ApiResponse.builder()
                            .success(true)
                            .message("로그인 성공")
                            .data(data)
                            .build()
            );

        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.builder()
                            .success(false)
                            .message("이메일 또는 비밀번호가 올바르지 않습니다.")
                            .build());
        }
    }

    // 토큰 갱신
    @PostMapping("/auth/refresh")
    public ResponseEntity<ApiResponse> refreshToken(HttpServletRequest request) {
        // 쿠키에서 Refresh Token 추출
        String refreshToken = extractRefreshTokenFromCookie(request);

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.builder()
                            .success(false)
                            .message("Refresh Token이 없습니다.")
                            .build());
        }

        if (!jwtUtil.validateToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.builder()
                            .success(false)
                            .message("유효하지 않은 Refresh Token입니다.")
                            .build());
        }

        String email = jwtUtil.getEmail(refreshToken);

        // DB에 저장된 Refresh Token과 비교
        if (!refreshTokenService.validateRefreshToken(email, refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.builder()
                            .success(false)
                            .message("Refresh Token이 일치하지 않습니다.")
                            .build());
        }

        // 새로운 Access Token 생성
        String newAccessToken = jwtUtil.createAccessToken(email);

        Map<String, String> data = new HashMap<>();
        data.put("accessToken", newAccessToken);

        return ResponseEntity.ok(
                ApiResponse.builder()
                        .success(true)
                        .message("토큰이 갱신되었습니다.")
                        .data(data)
                        .build()
        );
    }

    // 로그아웃
    @PostMapping("/auth/logout")
    public ResponseEntity<ApiResponse> logout(HttpServletRequest request, HttpServletResponse response) {
        // 쿠키에서 Refresh Token 추출
        String refreshToken = extractRefreshTokenFromCookie(request);

        if (refreshToken != null && jwtUtil.validateToken(refreshToken)) {
            String email = jwtUtil.getEmail(refreshToken);
            refreshTokenService.deleteRefreshToken(email);
        }

        // Refresh Token 쿠키 삭제
        removeRefreshTokenCookie(response);

        return ResponseEntity.ok(
                ApiResponse.builder()
                        .success(true)
                        .message("로그아웃 되었습니다.")
                        .build()
        );
    }

    // Refresh Token 쿠키 추가
    private void addRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);      // JavaScript 접근 차단
        cookie.setSecure(true);        // HTTPS에서만 전송
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7일
        response.addCookie(cookie);
    }

    // Refresh Token 쿠키 삭제
    private void removeRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0); // 즉시 만료
        response.addCookie(cookie);
    }

    // 쿠키에서 Refresh Token 추출
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
