package hashsnap.login.controller;

import hashsnap.global.response.ApiResponse;
import hashsnap.login.dto.*;
import hashsnap.login.entity.User;
import hashsnap.login.exception.EmailVerificationException;
import hashsnap.login.exception.UserException.DuplicateUserException;
import hashsnap.login.service.EmailVerificationService;
import hashsnap.login.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;


@RestController  // JSON 반환
@RequestMapping("/api")
@ResponseBody
@Slf4j
@RequiredArgsConstructor
public class UserApiController {

    private final UserService userService;
    private final EmailVerificationService emailVerificationService;

    // 이메일 중복 확인 API
    @GetMapping("/users")
    public ResponseEntity<EmailCheckResponse> checkEmailDuplicate(@RequestParam String email) {
        boolean exists = userService.isEmailExists(email);
        return ResponseEntity.ok(
                EmailCheckResponse.builder()
                        .exists(exists)
                        .build()
        );
    }

    @PostMapping("/users")
    public ResponseEntity<ApiResponse> signup(@Valid @RequestBody SignupRequestDto signupRequest) {
        try {
            // 이메일 인증 완료 여부 확인
            if (!emailVerificationService.isEmailVerified(signupRequest.getEmail(), "signup")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponse.builder()
                                .success(false)
                                .message("이메일 인증을 완료해주세요.")
                                .build());
            }

            userService.signup(signupRequest);
            return ResponseEntity.ok(
                    ApiResponse.builder()
                            .success(true)
                            .message("회원가입이 완료되었습니다")
                            .build()
            );
        } catch (DuplicateUserException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiResponse.builder()
                            .success(false)
                            .message(e.getMessage())
                            .build());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.builder()
                            .success(false)
                            .message("회원가입 중 오류가 발생했습니다")
                            .build());
        }
    }

    @PostMapping("/email-verification")
    public ResponseEntity<ApiResponse> handleEmailVerification(@Valid @RequestBody EmailVerificationDto request) {
        try {
            ApiResponse response = switch (request.getAction()) {
                case "send" -> handleSendAction(request);
                case "verify" -> handleVerifyAction(request);
                default -> createErrorResponse("잘못된 요청입니다");
            };

            // success가 false인 경우 BAD_REQUEST 상태 코드 반환
            HttpStatus status = response.isSuccess() ? HttpStatus.OK : HttpStatus.BAD_REQUEST;
            return ResponseEntity.status(status).body(response);

        } catch (EmailVerificationException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(createErrorResponse(e.getMessage()));
        } catch (Exception e) {
            log.error("이메일 인증 처리 중 오류 발생", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(createErrorResponse("처리 중 오류가 발생했습니다"));
        }
    }

    @GetMapping("/users/profile")
    public ResponseEntity<ApiResponse> getUserProfile(@RequestParam String email) {
        try {
            User user = userService.findByEmail(email);

            if (user == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(ApiResponse.builder()
                                .success(false)
                                .message("사용자를 찾을 수 없습니다.")
                                .build());
            }

            UserInfoResponseDto userInfo = UserInfoResponseDto.from(user);

            return ResponseEntity.ok(
                    ApiResponse.builder()
                            .success(true)
                            .message("사용자 정보 조회 성공")
                            .data(Map.of("user", userInfo))  // 이렇게 해야 data.user로 접근 가능
                            .build()
            );

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.builder()
                            .success(false)
                            .message("사용자 정보 조회 중 오류가 발생했습니다.")
                            .build());
        }
    }

    // 비밀번호 재설정 API
    @PutMapping("/users/password")
    public ResponseEntity<ApiResponse> resetPassword(@Valid @RequestBody PasswordResetDto request) {
        try {
            // 이메일 인증 여부 확인
            if (!emailVerificationService.isEmailVerified(request.getEmail(), "password-reset")) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(ApiResponse.builder()
                                .success(false)
                                .message("이메일 인증이 완료되지 않았습니다.")
                                .build());
            }

            userService.resetPassword(request.getEmail(), request.getNewPassword());

            return ResponseEntity.ok(
                    ApiResponse.builder()
                            .success(true)
                            .message("비밀번호가 성공적으로 재설정되었습니다.")
                            .build()
            );

        } catch (Exception e) {
            log.error("비밀번호 재설정 중 오류 발생", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.builder()
                            .success(false)
                            .message("비밀번호 재설정 중 오류가 발생했습니다.")
                            .build());
        }
    }

    private ApiResponse handleSendAction(EmailVerificationDto request) {
        if ("password-reset".equals(request.getPurpose()) && !userService.isEmailExists(request.getEmail())) {
            return createErrorResponse("존재하지 않는 메일입니다.");
        }

        emailVerificationService.sendVerificationCode(request.getEmail(), request.getPurpose());
        return createSuccessResponse("인증번호가 발송되었습니다");
    }

    private ApiResponse handleVerifyAction(EmailVerificationDto request) {
        if (request.getVerificationCode() == null || request.getVerificationCode().trim().isEmpty()) {
            return createErrorResponse("인증번호를 입력해주세요");
        }

        boolean isValid = emailVerificationService.verifyCode(
                request.getEmail(),
                request.getVerificationCode().trim(),
                request.getPurpose()
        );

        return isValid
                ? createSuccessResponse("인증이 완료되었습니다")
                : createErrorResponse("인증번호가 일치하지 않습니다");
    }

    // 응답 생성 헬퍼 메소드들
    private ApiResponse createSuccessResponse(String message) {
        return ApiResponse.builder()
                .success(true)
                .message(message)
                .build();
    }

    private ApiResponse createErrorResponse(String message) {
        return ApiResponse.builder()
                .success(false)
                .message(message)
                .build();
    }
}