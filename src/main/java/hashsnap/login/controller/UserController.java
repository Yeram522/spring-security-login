package hashsnap.login.controller;

import hashsnap.global.controller.ApiController;
import hashsnap.global.response.ApiResponse;
import hashsnap.global.security.UserDetailsImpl;
import hashsnap.global.util.ResponseUtils;
import hashsnap.login.dto.*;
import hashsnap.login.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * 사용자 관리 API 컨트롤러
 * 회원가입, 프로필 조회, 비밀번호 재설정 등
 * 사용자 관련 모든 REST API 엔드포인트 제공
 */
@RestController
@Slf4j
@RequiredArgsConstructor
@PreAuthorize("hasAnyRole('USER','ADMIN')")
public class UserController extends ApiController {

    private final UserService userService;

    /**
     * 이메일 중복 확인 API
     * @param email 유저 이메일
     * @return EmailCheckResponse
     */
    @GetMapping("/users")
    public ResponseEntity<ApiResponse<EmailCheckResponseDto>> checkEmailDuplicate(@RequestParam String email) {
        // 이메일 형식 검증
        if (!isValidEmail(email)) {
            return ResponseUtils.badRequest("올바른 이메일 형식이 아닙니다");
        }

        boolean exists = userService.isEmailExists(email);
        EmailCheckResponseDto response = EmailCheckResponseDto.builder()
                .exists(exists)
                .build();
        return ResponseUtils.ok("이메일 중복 확인 완료", response);
    }

    private boolean isValidEmail(String email) {
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
        return email != null && email.matches(emailRegex);
    }

    /**
     * 회원가입 API
     * @param signupRequest 회원가입 요청 DTO
     * @return result message
     */
    @PostMapping("/users")
    public ResponseEntity<ApiResponse<Void>> signup(@Valid @RequestBody SignupRequestDto signupRequest) {
        userService.signup(signupRequest);
        return ResponseUtils.ok("회원가입이 완료되었습니다");
    }

    /**
     * 현재 로그인한 사용자 정보 조회 API
     * @param userDetails 인증된 사용자 정보
     * @return UserInfoResponseDto
     */
    @GetMapping("/users/me")
    public ResponseEntity<ApiResponse<UserInfoResponseDto>> getCurrentUserInfo(
            @AuthenticationPrincipal UserDetailsImpl userDetails) {

        String email = userDetails.getUsername(); // 이메일
        UserInfoResponseDto userInfo = userService.getUserInfo(email);
        return ResponseUtils.ok("사용자 정보 조회 성공", userInfo);
    }

    /**
     * 비밀번호 재설정 API
     * @param request 새 비밀번호 DTO
     * @return result message
     */
    @PutMapping("/users/password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody PasswordResetDto request) {
        userService.resetPassword(request.getEmail(), request.getNewPassword());
        return ResponseUtils.ok("비밀번호가 성공적으로 재설정되었습니다");
    }


}