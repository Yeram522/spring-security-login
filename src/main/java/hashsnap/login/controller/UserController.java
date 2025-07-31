package hashsnap.login.controller;

import hashsnap.global.controller.ApiController;
import hashsnap.global.response.ApiResponse;
import hashsnap.global.util.ResponseUtils;
import hashsnap.login.dto.*;
import hashsnap.login.entity.User;
import hashsnap.login.exception.EmailVerificationException;
import hashsnap.login.service.EmailVerificationService;
import hashsnap.login.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;


@RestController  // JSON 반환
@ResponseBody
@Slf4j
@RequiredArgsConstructor
public class UserController extends ApiController {

    private final UserService userService;
    private final EmailVerificationService emailVerificationService;

    /**
     * 이메일 중복 확인 API
     * @param email 유저 이메일
     * @return EmailCheckResponse
     */
    @GetMapping("/users")
    public ResponseEntity<ApiResponse<EmailCheckResponse>> checkEmailDuplicate(@RequestParam String email) {
        boolean exists = userService.isEmailExists(email);
        EmailCheckResponse response = EmailCheckResponse.builder()
                .exists(exists)
                .build();
        return ResponseUtils.ok("이메일 중복 확인 완료", response);
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
     * 유저 프로필 조회 API
     * @param email 유저 이메일
     * @return map: UserInfoResponseDto -> comment. 반환 형식 수정하는게 좋을 듯
     */
    @GetMapping("/users/profile")
    public ResponseEntity<ApiResponse<Map<String, UserInfoResponseDto>>> getUserProfile(@RequestParam String email) {
        User user = userService.findByEmail(email);

        if (user == null) {
            return ResponseUtils.notFound("사용자를 찾을 수 없습니다");
        }

        UserInfoResponseDto userInfo = UserInfoResponseDto.from(user);
        Map<String, UserInfoResponseDto> data = Map.of("user", userInfo);

        return ResponseUtils.ok("사용자 정보 조회 성공", data);
    }

    /**
     * 비밀번호 재설정 API
     * @param request 새 비밀번호 DTO
     * @return result message
     */
    @PutMapping("/users/password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody PasswordResetDto request) {
        try {
            if (!emailVerificationService.isEmailVerified(request.getEmail(), "password-reset")) {
                return ResponseUtils.badRequest("이메일 인증이 완료되지 않았습니다");
            }

            userService.resetPassword(request.getEmail(), request.getNewPassword());
            return ResponseUtils.ok("비밀번호가 성공적으로 재설정되었습니다");

        } catch (Exception e) {
            log.error("비밀번호 재설정 중 오류 발생", e);
            return ResponseUtils.internalServerError("비밀번호 재설정 중 오류가 발생했습니다");
        }
    }

    /**
     * 이메일 인증 API( 인증번호 발송, 인증번호 확인 )
     * @param request 이메일 인증 DTO
     * @return result message
     */
    @PostMapping("/email-verification")
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
}